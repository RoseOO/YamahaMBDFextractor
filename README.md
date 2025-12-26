# Yamaha MBDFArchive Extractor

A GUI tool for extracting files from Yamaha MBDFArchive container files.

## Overview

This tool extracts embedded files from Yamaha `#YAMAHA MBDFArchive` container files, commonly found in Yamaha firmware and data files (`.bin` files). It supports:

- **#FILE blocks**: Files with 48-byte headers followed by filenames and zlib-compressed data
- **#FIRMWARE blocks**: Firmware data with metadata and zlib-compressed payloads
- **Nested archives**: Automatically detects and extracts nested MBDFArchive containers (1 level deep)

## Requirements

- Python 3.x
- tkinter (usually included with Python)

Standard library modules used:
- `tkinter` for GUI
- `zlib` for decompression
- `pathlib`, `os`, `re`, `sys`, `dataclasses`, `typing`

## Usage

1. Run the program:
   ```bash
   python3 yamaha_extractor.py
   ```

2. In the GUI:
   - Click **"Add .bin file(s)…"** to select one or more Yamaha MBDFArchive files
   - Click **"Choose output folder…"** to select where extracted files should be saved
   - Click **"Preview contents"** to see what files are embedded in the archive(s)
   - Click **"Extract (1 level deep)"** to extract all files

3. The tool will:
   - Extract all embedded files to the output folder
   - Automatically detect and extract nested archives into subfolders
   - Show detailed logs of the extraction process

## Features

- **Multi-file support**: Process multiple archive files in one session
- **Preview**: View embedded file names and structure before extracting
- **Nested archive handling**: Automatically detects and extracts nested MBDFArchive containers
- **Collision handling**: Automatically renames files if output names conflict
- **Error recovery**: Saves raw compressed data if decompression fails
- **Cross-platform**: Works on Windows, macOS, and Linux

## Output

Extracted files are saved to the chosen output folder with their original names (sanitized for filesystem compatibility). If an extracted file contains a nested MBDFArchive, it will be automatically extracted into a subfolder named `<filename>_extracted/`.

## License

This tool is provided as-is for working with Yamaha MBDFArchive files.
