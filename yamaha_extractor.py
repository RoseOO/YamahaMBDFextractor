#!/usr/bin/env python3
"""
Yamaha MBDFArchive extractor (GUI)

- Extracts Yamaha "#YAMAHA MBDFArchive" containers supporting:
  - #FILE blocks (48-byte header, then filename, then zlib member)
  - #FIRMWARE blocks (metadata then zlib member; name may be absent)
"""

from __future__ import annotations

import os
import re
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import ttk, filedialog, messagebox


MAGIC_ARCHIVE = b"#YAMAHA MBDFArchive"
MAGIC_FILE = b"#FILE"
MAGIC_FIRMWARE = b"#FIRMWARE"
FILE_HDR_LEN = 48

ZLIB_HEADS = (b"\x78\x01", b"\x78\x9c", b"\x78\xda")
ZLIB_HEADS_PADDED = (b"\x00\x78\x01", b"\x00\x78\x9c", b"\x00\x78\xda")

MARKERS = (MAGIC_FILE, MAGIC_FIRMWARE)


@dataclass
class EmbeddedFile:
    name: str
    start_offset: int
    end_offset: int
    marker_offset: int
    marker: bytes


def _safe_output_name(stored_name: str) -> str:
    base = stored_name.replace("\\", "/").split("/")[-1]
    if not base:
        base = "payload.bin"
    base = re.sub(r"[^A-Za-z0-9._+-]+", "_", base)
    return base


def _safe_folder_name(filename: str) -> str:
    name = Path(filename).name
    name = re.sub(r"[^A-Za-z0-9._+-]+", "_", name).strip("._ ")
    return name or "nested"


def _find_next_marker(data: bytes, start: int) -> Optional[Tuple[int, bytes]]:
    best_off = None
    best_m = None
    for m in MARKERS:
        off = data.find(m, start)
        if off != -1 and (best_off is None or off < best_off):
            best_off = off
            best_m = m
    if best_off is None:
        return None
    return best_off, best_m  # type: ignore


def _find_zlib_start(data: bytes, start: int, end: int, max_scan: int = 1024 * 1024) -> Optional[int]:
    scan_end = min(end, start + max_scan)
    window = data[start:scan_end]

    best = None
    for zh in ZLIB_HEADS:
        p = window.find(zh)
        if p != -1:
            best = p if best is None else min(best, p)
    for zh in ZLIB_HEADS_PADDED:
        p = window.find(zh)
        if p != -1:
            best = p if best is None else min(best, p)

    if best is None:
        return None
    return start + best


def _extract_printable_label(data: bytes, start: int, end: int, max_scan: int = 1024) -> Optional[str]:
    scan_end = min(end, start + max_scan)
    chunk = data[start:scan_end]

    m = re.search(rb"/[A-Za-z0-9._+-]{3,120}", chunk)
    if m:
        return m.group(0).decode("utf-8", errors="replace")

    m2 = re.search(rb"[A-Za-z0-9][A-Za-z0-9._+-]{6,120}", chunk)
    if m2:
        return m2.group(0).decode("utf-8", errors="replace")

    return None


def _guess_name_from_file_block(data: bytes, name_start: int, block_end: int) -> Tuple[Optional[str], Optional[int]]:
    scan_end = min(block_end, name_start + 512)
    window = data[name_start:scan_end]

    candidates = []

    nul = window.find(b"\x00")
    if nul != -1:
        candidates.append(nul)

    for zh in ZLIB_HEADS:
        pos = window.find(zh)
        if pos != -1:
            candidates.append(pos)

    for zh in ZLIB_HEADS_PADDED:
        pos = window.find(zh)
        if pos != -1:
            candidates.append(pos)

    if not candidates:
        return None, None

    boundary = min(candidates)
    raw_name = window[:boundary]

    if not raw_name.startswith(b"/"):
        return None, None

    name = raw_name.decode("utf-8", errors="replace")
    payload_start = name_start + boundary
    return name, payload_start


def _decompress_zlib_member(data: bytes, start: int, end: int) -> Tuple[bytes, int]:
    blob = data[start:end]

    if len(blob) >= 3 and blob[0] == 0x00 and blob[1:3] in ZLIB_HEADS:
        start += 1
        blob = data[start:end]

    decomp = zlib.decompressobj()
    out = decomp.decompress(blob)
    out += decomp.flush()

    if not decomp.eof:
        raise zlib.error("zlib stream did not reach EOF within block bounds")

    compressed_len = len(blob) - len(decomp.unused_data)
    compressed_end = start + compressed_len
    return out, compressed_end


def _is_mbdf_archive_bytes(b: bytes) -> bool:
    return MAGIC_ARCHIVE in b[:2048]


def parse_mbdf_archive(data: bytes) -> List[EmbeddedFile]:
    embedded: List[EmbeddedFile] = []
    cursor = 0
    firmware_counter = 0

    while True:
        hit = _find_next_marker(data, cursor)
        if hit is None:
            break

        m_off, marker = hit

        if marker == MAGIC_FILE:
            if m_off + FILE_HDR_LEN + 1 >= len(data):
                cursor = m_off + len(marker)
                continue

            next_hit = _find_next_marker(data, m_off + 1)
            block_bound = next_hit[0] if next_hit is not None else len(data)

            name_start = m_off + FILE_HDR_LEN
            name, payload_guess = _guess_name_from_file_block(data, name_start, block_bound)
            if not name or payload_guess is None:
                cursor = m_off + len(marker)
                continue

            zstart = _find_zlib_start(data, payload_guess, len(data), max_scan=64 * 1024)
            if zstart is None:
                cursor = m_off + len(marker)
                continue

            try:
                _payload, z_end = _decompress_zlib_member(data, zstart, len(data))
            except zlib.error:
                cursor = m_off + len(marker)
                continue

            embedded.append(
                EmbeddedFile(
                    name=name,
                    start_offset=zstart,
                    end_offset=z_end,
                    marker_offset=m_off,
                    marker=marker,
                )
            )
            cursor = z_end
            continue

        if marker == MAGIC_FIRMWARE:
            scan_start = m_off + len(MAGIC_FIRMWARE)

            label = _extract_printable_label(data, scan_start, min(len(data), scan_start + 4096))
            if not label:
                firmware_counter += 1
                label = f"/FIRMWARE_{firmware_counter:04d}.bin"

            zstart = _find_zlib_start(data, scan_start, len(data), max_scan=1024 * 1024)
            if zstart is None:
                cursor = m_off + len(marker)
                continue

            try:
                _payload, z_end = _decompress_zlib_member(data, zstart, len(data))
            except zlib.error:
                cursor = m_off + len(marker)
                continue

            embedded.append(
                EmbeddedFile(
                    name=label,
                    start_offset=zstart,
                    end_offset=z_end,
                    marker_offset=m_off,
                    marker=marker,
                )
            )
            cursor = z_end
            continue

        cursor = m_off + len(marker)

    return embedded


def extract_one(data: bytes, ef: EmbeddedFile) -> bytes:
    payload, _ = _decompress_zlib_member(data, ef.start_offset, ef.end_offset)
    return payload


def extract_archive_bytes_to_folder(data: bytes, outdir: Path, log_cb):
    outdir.mkdir(parents=True, exist_ok=True)

    embedded = parse_mbdf_archive(data)
    log_cb(f"  Nested archive: found {len(embedded)} embedded block(s).")

    for ef in embedded:
        safe = _safe_output_name(ef.name)
        out_path = outdir / safe

        if out_path.exists():
            stem = out_path.stem
            suf = out_path.suffix
            k = 1
            while True:
                candidate = outdir / f"{stem}_{k}{suf}"
                if not candidate.exists():
                    out_path = candidate
                    break
                k += 1

        try:
            payload = extract_one(data, ef)
        except zlib.error as e:
            raw_path = outdir / (out_path.name + ".raw")
            try:
                raw_path.write_bytes(data[ef.start_offset:ef.end_offset])
                log_cb(f"  [ERROR] Nested zlib failed for {ef.name}: {e} (wrote {raw_path.name})")
            except Exception as we:
                log_cb(f"  [ERROR] Nested zlib failed for {ef.name}: {e} (also failed writing raw: {we})")
            continue

        out_path.write_bytes(payload)
        log_cb(f"  [OK] {ef.name} -> {out_path.name} ({len(payload):,} bytes)")


class App(ttk.Frame):
    def __init__(self, master: tk.Tk):
        super().__init__(master)
        self.master = master
        self.master.title("Yamaha MBDFArchive Extractor")
        self.master.geometry("1180x600")

        self.input_files: List[Path] = []
        self.output_dir: Optional[Path] = None

        # Preview cache: map from displayed list index -> (source_file_path, EmbeddedFile)
        self._preview_entries: List[Tuple[Path, EmbeddedFile]] = []
        # Nested preview cache: map from list index -> list of nested EmbeddedFile
        self._nested_preview: Dict[int, List[EmbeddedFile]] = {}

        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 8, "pady": 6}

        top = ttk.Frame(self)
        top.pack(fill="x", **pad)

        ttk.Button(top, text="Add .bin file(s)…", command=self.add_files).pack(side="left")
        ttk.Button(top, text="Clear list", command=self.clear_files).pack(side="left", padx=(8, 0))

        out = ttk.Frame(self)
        out.pack(fill="x", **pad)

        ttk.Button(out, text="Choose output folder…", command=self.choose_output).pack(side="left")
        self.out_label = ttk.Label(out, text="(no output folder chosen)")
        self.out_label.pack(side="left", padx=(10, 0), fill="x", expand=True)

        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, **pad)

        # LEFT: input files
        left = ttk.Frame(mid)
        left.pack(side="left", fill="both", expand=True)

        ttk.Label(left, text="Input files").pack(anchor="w")
        self.files_list = tk.Listbox(left, height=10)
        self.files_list.pack(fill="both", expand=True)

        # CENTER: embedded contents
        center = ttk.Frame(mid)
        center.pack(side="left", fill="both", expand=True, padx=(10, 0))

        ttk.Label(center, text="Embedded contents (preview)").pack(anchor="w")
        self.contents = tk.Listbox(center, height=10)
        self.contents.pack(fill="both", expand=True)
        self.contents.bind("<<ListboxSelect>>", self.on_select_embedded)

        # RIGHT: nested embedded contents
        right = ttk.Frame(mid)
        right.pack(side="left", fill="both", expand=True, padx=(10, 0))

        ttk.Label(right, text="Nested contents (1 level) of selected item").pack(anchor="w")
        self.nested = tk.Listbox(right, height=10)
        self.nested.pack(fill="both", expand=True)

        actions = ttk.Frame(self)
        actions.pack(fill="x", **pad)

        ttk.Button(actions, text="Preview contents", command=self.preview).pack(side="left")
        ttk.Button(actions, text="Extract (1 level deep)", command=self.extract).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Open output folder", command=self.open_output).pack(side="left", padx=(8, 0))

        ttk.Separator(self).pack(fill="x", padx=8, pady=(6, 0))

        logf = ttk.Frame(self)
        logf.pack(fill="both", expand=True, padx=8, pady=8)

        ttk.Label(logf, text="Log").pack(anchor="w")
        self.log = tk.Text(logf, height=12, wrap="word")
        self.log.pack(fill="both", expand=True)

        self.pack(fill="both", expand=True)

    def log_line(self, s: str):
        self.log.insert("end", s + "\n")
        self.log.see("end")
        self.master.update_idletasks()

    def add_files(self):
        paths = filedialog.askopenfilenames(
            title="Select Yamaha MBDFArchive .bin file(s)",
            filetypes=[("BIN files", "*.bin"), ("All files", "*.*")],
        )
        if not paths:
            return

        for p in paths:
            pp = Path(p)
            if pp not in self.input_files:
                self.input_files.append(pp)
                self.files_list.insert("end", str(pp))

        self.log_line(f"Added {len(paths)} file(s).")

    def clear_files(self):
        self.input_files.clear()
        self.files_list.delete(0, "end")
        self.contents.delete(0, "end")
        self.nested.delete(0, "end")
        self._preview_entries.clear()
        self._nested_preview.clear()
        self.log_line("Cleared input file list.")

    def choose_output(self):
        p = filedialog.askdirectory(title="Choose output folder")
        if not p:
            return
        self.output_dir = Path(p)
        self.out_label.configure(text=str(self.output_dir))
        self.log_line(f"Output folder: {self.output_dir}")

    def preview(self):
        self.contents.delete(0, "end")
        self.nested.delete(0, "end")
        self._preview_entries.clear()
        self._nested_preview.clear()

        if not self.input_files:
            messagebox.showinfo("Nothing to preview", "Add one or more .bin files first.")
            return

        total = 0
        for f in self.input_files:
            try:
                data = f.read_bytes()
            except Exception as e:
                self.log_line(f"[ERROR] Reading {f}: {e}")
                continue

            if MAGIC_ARCHIVE not in data[:2048]:
                self.log_line(f"[WARN] {f.name}: MBDF header not found near start (still attempting parse).")

            embedded = parse_mbdf_archive(data)
            self.log_line(f"{f.name}: found {len(embedded)} embedded block(s).")

            for ef in embedded:
                idx = len(self._preview_entries)
                self._preview_entries.append((f, ef))

                total += 1
                mtag = ef.marker.decode("ascii", errors="replace")
                # Show human-friendly line
                shown = f"{f.name}  ->  {ef.name}   [{mtag}]"
                self.contents.insert("end", shown)

                # Precompute nested preview if possible (one level) for responsiveness
                try:
                    payload = extract_one(data, ef)
                    if _is_mbdf_archive_bytes(payload):
                        nested_list = parse_mbdf_archive(payload)
                        self._nested_preview[idx] = nested_list
                except Exception:
                    # ignore preview-time errors; user can still extract
                    pass

        if total == 0:
            self.log_line("No embedded blocks found. Format may differ from known MBDF variants.")

    def on_select_embedded(self, _evt):
        self.nested.delete(0, "end")
        sel = self.contents.curselection()
        if not sel:
            return
        i = int(sel[0])

        nested = self._nested_preview.get(i)
        if not nested:
            self.nested.insert("end", "(no nested MBDF archive detected)")
            return

        self.nested.insert("end", f"(nested MBDF archive: {len(nested)} item(s))")
        for ef in nested:
            mtag = ef.marker.decode("ascii", errors="replace")
            self.nested.insert("end", f"{ef.name}   [{mtag}]")

    def extract(self):
        if not self.input_files:
            messagebox.showinfo("Nothing to extract", "Add one or more .bin files first.")
            return
        if not self.output_dir:
            messagebox.showinfo("No output folder", "Choose an output folder first.")
            return

        outdir = self.output_dir
        outdir.mkdir(parents=True, exist_ok=True)

        extracted = 0
        for f in self.input_files:
            self.log_line(f"--- Extracting from: {f} ---")
            try:
                data = f.read_bytes()
            except Exception as e:
                self.log_line(f"[ERROR] Reading {f}: {e}")
                continue

            embedded = parse_mbdf_archive(data)
            if not embedded:
                self.log_line("[WARN] No embedded blocks found in this input.")
                continue

            for ef in embedded:
                safe = _safe_output_name(ef.name)
                out_path = outdir / safe

                if out_path.exists():
                    stem = out_path.stem
                    suf = out_path.suffix
                    k = 1
                    while True:
                        candidate = outdir / f"{stem}_{k}{suf}"
                        if not candidate.exists():
                            out_path = candidate
                            break
                        k += 1

                try:
                    payload = extract_one(data, ef)
                except zlib.error as e:
                    raw_path = outdir / (out_path.name + ".raw")
                    try:
                        raw_path.write_bytes(data[ef.start_offset:ef.end_offset])
                        self.log_line(f"[ERROR] zlib failed for {ef.name}: {e} (wrote raw blob: {raw_path.name})")
                    except Exception as we:
                        self.log_line(f"[ERROR] zlib failed for {ef.name}: {e} (also failed writing raw: {we})")
                    continue
                except Exception as e:
                    self.log_line(f"[ERROR] Extract failed for {ef.name}: {e}")
                    continue

                out_path.write_bytes(payload)
                extracted += 1
                self.log_line(f"[OK] {ef.name}  ->  {out_path.name}  ({len(payload):,} bytes)")

                # ONE LEVEL DEEP: if extracted payload is itself an MBDFArchive, extract into subfolder "<name>_extracted"
                if _is_mbdf_archive_bytes(payload):
                    subfolder = outdir / (_safe_folder_name(out_path.name) + "_extracted")
                    self.log_line(f"  Detected nested MBDFArchive in {out_path.name} -> extracting into {subfolder.name}/")
                    try:
                        extract_archive_bytes_to_folder(payload, subfolder, self.log_line)
                    except Exception as e:
                        self.log_line(f"  [ERROR] Nested extraction failed: {e}")

        self.log_line(f"Done. Extracted {extracted} file(s) into: {outdir}")
        if extracted:
            messagebox.showinfo("Extraction complete", f"Extracted {extracted} file(s) into:\n{outdir}")

    def open_output(self):
        if not self.output_dir:
            messagebox.showinfo("No output folder", "Choose an output folder first.")
            return
        p = str(self.output_dir)
        try:
            if sys.platform.startswith("win"):
                os.startfile(p)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                os.system(f'open "{p}"')
            else:
                os.system(f'xdg-open "{p}"')
        except Exception as e:
            messagebox.showerror("Open folder failed", str(e))


def main():
    root = tk.Tk()
    try:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass

    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
