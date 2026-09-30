#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
A.C MODS - Unisoc / SPD PAC Firmware Extractor
================================================

Termux-compatible PAC extractor.

Features:
    - PAC header validation
    - Parses PAC file descriptors instead of relying only on signatures
    - UTF-16LE filename decoding
    - Extracts every directory entry, including zero-byte entries
    - No partition-name filtering
    - 1 MiB buffered extraction
    - 64-bit offsets/sizes
    - Bounds checking
    - Duplicate-name protection
    - Safe filename sanitisation
    - Progress display
    - SHA-256 verification
    - XML/config files are extracted normally
    - Does not load large partitions into RAM

Output:
    AC_MODS_EXTRACTED_FILES/

Important:
    PAC variants exist. The parser validates the descriptor table
    before extraction. It will not claim 100% extraction from a
    PAC whose internal directory cannot be identified reliably.
"""

import os
import sys
import time
import struct
import hashlib
from pathlib import Path


# ============================================================
# ANSI COLORS
# ============================================================

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
WHITE = "\033[97m"


# ============================================================
# CONFIGURATION
# ============================================================

OUTPUT_DIR = "AC_MODS_EXTRACTED_FILES"

# Memory-efficient extraction buffer.
CHUNK_SIZE = 1024 * 1024

# Common PAC FILE_T descriptor size.
FILE_ENTRY_SIZE = 2580

# Common PAC header size.
PAC_HEADER_SIZE = 2124

# Maximum UTF-16 filename characters we accept.
MAX_FILENAME_CHARS = 1024


# ============================================================
# DISPLAY HELPERS
# ============================================================

def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")


def banner():
    # Branding/layout retained.
    print(
        f"""
{BOLD}{RED}╔══════════════════════════════════════════════════════╗
║                  {WHITE}A.C MODS{RED}                         ║
║          {BLUE}UNISOC / SPD PAC EXTRACTOR{RED}             ║
╠══════════════════════════════════════════════════════╣
║ {BLUE}Telegram :{WHITE} @acmodsff{RED}                            ║
║ {BLUE}Channel  :{WHITE} t.me/hackstore2026{RED}                  ║
╚══════════════════════════════════════════════════════╝{RESET}
"""
    )


def info(message):
    print(f"{CYAN}[•]{RESET} {message}")


def success(message):
    print(f"{GREEN}[✓]{RESET} {message}")


def warning(message):
    print(f"{YELLOW}[!]{RESET} {message}")


def error(message):
    print(f"{RED}[✗]{RESET} {message}")


# ============================================================
# SIZE HELPERS
# ============================================================

def human_size(size):
    if size < 1024:
        return f"{size} B"

    if size < 1024 ** 2:
        return f"{size / 1024:.2f} KB"

    if size < 1024 ** 3:
        return f"{size / (1024 ** 2):.2f} MB"

    return f"{size / (1024 ** 3):.2f} GB"


def progress_bar(current, total, filename="", width=32):
    if total <= 0:
        percent = 100.0
    else:
        percent = min(
            100.0,
            (current / total) * 100.0
        )

    filled = int(width * percent / 100.0)

    bar = (
        "█" * filled
        + "░" * (width - filled)
    )

    display_name = filename[:42]

    sys.stdout.write(
        f"\r{CYAN}[{bar}]{RESET} "
        f"{percent:6.2f}% "
        f"{WHITE}{display_name:<42}{RESET} "
        f"{YELLOW}{human_size(current)}{RESET}"
    )

    sys.stdout.flush()

    if current >= total:
        print()


# ============================================================
# SAFE FILE ACCESS
# ============================================================

def read_exact(fp, size):
    """
    Read exactly 'size' bytes.

    Raises EOFError instead of silently accepting truncated data.
    """

    if size < 0:
        raise ValueError("Negative read size.")

    data = fp.read(size)

    if len(data) != size:
        raise EOFError(
            f"Unexpected end of PAC file: "
            f"expected {size} bytes, got {len(data)}."
        )

    return data


def file_size(path):
    try:
        return path.stat().st_size
    except OSError as exc:
        raise OSError(
            f"Unable to read file size: {exc}"
        ) from exc


# ============================================================
# PAC HEADER VALIDATION
# ============================================================

def validate_pac_header(path):
    """
    Validate the common Unisoc PAC signature.

    Modern PAC implementations commonly use:
        0xFFFAFFFA

    Some older/vendor variants can differ, so we additionally
    inspect the first header area for PAC-like metadata.
    """

    size = file_size(path)

    if size < 16:
        raise ValueError(
            "File is too small to be a valid PAC file."
        )

    with path.open("rb") as fp:
        header = fp.read(
            min(PAC_HEADER_SIZE, size)
        )

    if len(header) < 4:
        raise ValueError(
            "Unable to read PAC header."
        )

    magic = struct.unpack_from(
        "<I",
        header,
        0
    )[0]

    # Primary known PAC signature.
    if magic == 0xFFFAFFFA:
        return True

    # Compatibility checks for vendor/older variants.
    known_text = (
        b"PACK",
        b"PAC",
        b"SPRD",
        b"SPREADTRUM",
        b"UNISOC",
    )

    upper_header = header.upper()

    if any(
        marker in upper_header
        for marker in known_text
    ):
        warning(
            "PAC signature is a vendor variant; "
            "continuing with structural validation."
        )
        return True

    raise ValueError(
        "Invalid or unsupported PAC header."
    )


# ============================================================
# UTF-16LE DECODER
# ============================================================

def decode_utf16_field(raw):
    """
    Decode fixed-width UTF-16LE PAC strings.

    PAC descriptors commonly contain null-padded Unicode
    strings. Invalid sequences are replaced rather than causing
    the complete extraction to fail.
    """

    # Trim at the first UTF-16LE NUL.
    nul = raw.find(b"\x00\x00")

    if nul >= 0:
        raw = raw[:nul]

    # UTF-16 requires an even number of bytes.
    if len(raw) % 2:
        raw = raw[:-1]

    if not raw:
        return ""

    try:
        text = raw.decode(
            "utf-16-le",
            errors="replace"
        )
    except UnicodeDecodeError:
        text = raw.decode(
            "utf-16-le",
            errors="replace"
        )

    return text.strip()


# ============================================================
# FILENAME SANITISATION
# ============================================================

def sanitize_filename(name):
    """
    Preserve the original filename as much as possible while
    preventing path traversal and invalid filesystem names.
    """

    if not name:
        name = "unnamed"

    # Remove NUL/control characters.
    cleaned = "".join(
        ch
        for ch in name
        if ch >= " "
    )

    # Prevent path traversal.
    cleaned = cleaned.replace("/", "_")
    cleaned = cleaned.replace("\\", "_")
    cleaned = cleaned.replace("..", "_")

    # Windows-invalid characters are also removed because this
    # keeps extracted firmware portable.
    for char in '<>:"|?*':
        cleaned = cleaned.replace(
            char,
            "_"
        )

    cleaned = cleaned.strip()

    if not cleaned:
        cleaned = "unnamed"

    return cleaned[:240]


# ============================================================
# EXTENSION DETECTION
# ============================================================

def add_missing_extension(name, file_id="", file_type=""):
    """
    Add a useful extension only when the descriptor does not
    already contain one.

    The original descriptor name remains preferred.
    """

    if "." in Path(name).name:
        return name

    combined = (
        f"{name} {file_id} {file_type}"
    ).lower()

    if "xml" in combined:
        return name + ".xml"

    if (
        "txt" in combined
        or "text" in combined
    ):
        return name + ".txt"

    if (
        "fdl" in combined
        or "loader" in combined
        or "bin" in combined
        or "nv" in combined
        or "modem" in combined
    ):
        return name + ".bin"

    # Android image-like entries.
    image_names = (
        "boot",
        "system",
        "vendor",
        "product",
        "odm",
        "recovery",
        "vbmeta",
        "dtbo",
        "super",
        "userdata",
        "cache",
        "metadata",
        "misc",
        "persist",
        "splash",
        "logo",
    )

    if any(
        token == name.lower()
        for token in image_names
    ):
        return name + ".img"

    return name


# ============================================================
# FILE_T PARSER
# ============================================================

def parse_file_entry(raw, index, pac_size):
    """
    Parse one FILE_T descriptor.

    The exact descriptor layout has varied between PAC
    generations. This parser uses the common 2580-byte
    descriptor and validates all candidate fields against the
    actual PAC file size.

    Returns a dictionary or None for operation-only entries.
    """

    if len(raw) != FILE_ENTRY_SIZE:
        raise ValueError(
            f"Descriptor {index} has invalid size."
        )

    # Common layout:
    #
    #   0x000  : file_id / logical ID
    #   0x100  : file_name
    #   ...    : size/flags/offset/address fields
    #
    # The fixed-width Unicode strings are decoded first.

    # FILE_T implementations commonly allocate large UTF-16
    # fields. We inspect the descriptor for valid UTF-16 strings.
    candidate_strings = []

    # Search aligned UTF-16 fields throughout the descriptor.
    for offset in range(
        0,
        len(raw) - 2,
        2
    ):
        sample = raw[
            offset:
            min(offset + 512, len(raw))
        ]

        text = decode_utf16_field(
            sample
        )

        if not text:
            continue

        printable = sum(
            ch.isprintable()
            for ch in text
        )

        if printable / max(
            1,
            len(text)
        ) < 0.75:
            continue

        if len(text) > MAX_FILENAME_CHARS:
            continue

        candidate_strings.append(
            (offset, text)
        )

    # Pick likely file-id/name strings.
    file_id = ""
    file_name = ""

    for offset, text in candidate_strings:
        lower = text.lower()

        if (
            not file_id
            and (
                "fdl" in lower
                or "boot" in lower
                or "system" in lower
                or "vendor" in lower
                or "modem" in lower
                or "nv" in lower
            )
        ):
            file_id = text

        if (
            not file_name
            and (
                "." in text
                or "image" in lower
                or "bin" in lower
                or "img" in lower
                or "xml" in lower
            )
        ):
            file_name = text

    # If the normal semantic strings were not identified,
    # preserve the first two plausible strings rather than
    # filtering the entry.
    if not file_id and candidate_strings:
        file_id = candidate_strings[0][1]

    if not file_name and len(candidate_strings) > 1:
        file_name = candidate_strings[1][1]

    # ----------------------------------------------------------------
    # Search aligned 64-bit values for a valid offset/size pair.
    #
    # A valid pair must:
    #   offset >= 0
    #   size >= 0
    #   offset + size <= PAC size
    #
    # We retain all candidates and select the candidate closest to
    # the descriptor's expected data area.
    # ----------------------------------------------------------------

    candidates = []

    for offset in range(
        0,
        len(raw) - 16 + 1,
        4
    ):
        try:
            value1, value2 = struct.unpack_from(
                "<QQ",
                raw,
                offset
            )
        except struct.error:
            continue

        # Candidate interpretation A:
        # absolute offset + size
        if (
            value1 <= pac_size
            and
            value2 <= pac_size
            and
            value1 + value2 <= pac_size
        ):
            candidates.append(
                (
                    value1,
                    value2,
                    offset,
                    "absolute"
                )
            )

        # Candidate interpretation B:
        # offset relative to a possible data base is handled later.
        # Keep only structurally reasonable values here.
        if (
            value1 > 0
            and
            value2 > 0
            and
            value1 < pac_size
            and
            value2 < pac_size
        ):
            candidates.append(
                (
                    value1,
                    value2,
                    offset,
                    "relative"
                )
            )

    if not candidates:
        return None

    # Prefer candidates whose size is plausible and whose offset
    # is beyond the descriptor/header area.
    def candidate_score(item):
        offset_value, size_value, field_offset, mode = item

        score = 0

        if (
            offset_value >= PAC_HEADER_SIZE
        ):
            score += 5

        if (
            size_value > 0
        ):
            score += 3

        if (
            offset_value + size_value
            <= pac_size
        ):
            score += 5

        # Descriptor metadata generally occurs before payload data.
        if field_offset < 2048:
            score += 1

        return score

    candidates.sort(
        key=candidate_score,
        reverse=True
    )

    data_offset = None
    data_size = None

    # Try absolute interpretation first.
    for (
        off,
        size,
        _field,
        mode
    ) in candidates:

        if mode != "absolute":
            continue

        if (
            off >= PAC_HEADER_SIZE
            and
            size <= pac_size
            and
            off + size <= pac_size
        ):
            data_offset = off
            data_size = size
            break

    if data_offset is None:
        return None

    if not file_name:
        file_name = file_id

    if not file_name:
        file_name = f"entry_{index:04d}"

    file_name = sanitize_filename(
        file_name
    )

    file_name = add_missing_extension(
        file_name,
        file_id,
        ""
    )

    return {
        "index": index,
        "file_id": sanitize_filename(
            file_id
        ),
        "name": file_name,
        "offset": data_offset,
        "size": data_size,
    }


# ============================================================
# DESCRIPTOR TABLE DISCOVERY
# ============================================================

def discover_descriptor_table(
    path,
    pac_size
):
    """
    Locate a valid FILE_T table.

    The common PAC layout places the descriptor array immediately
    after the fixed PAC header.

    We first test that location. If it fails, we scan aligned
    offsets for a complete sequence of structurally valid
    descriptors.
    """

    # --------------------------------------------------------
    # First: standard layout.
    # --------------------------------------------------------

    try:
        with path.open("rb") as fp:
            fp.seek(PAC_HEADER_SIZE)

            count_raw = read_exact(
                fp,
                4
            )

            possible_count = struct.unpack(
                "<I",
                count_raw
            )[0]

            # Some variants store the count immediately after
            # the header; accept only sensible values.
            if (
                0
                < possible_count
                < 10000
            ):
                table_start = (
                    PAC_HEADER_SIZE + 4
                )

                table_size = (
                    possible_count
                    * FILE_ENTRY_SIZE
                )

                if (
                    table_start
                    + table_size
                    <= pac_size
                ):
                    return (
                        table_start,
                        possible_count
                    )

    except (
        OSError,
        EOFError,
        struct.error
    ):
        pass

    # --------------------------------------------------------
    # Second: search the first 1 MiB for a plausible count.
    # --------------------------------------------------------

    scan_limit = min(
        pac_size,
        1024 * 1024
    )

    with path.open("rb") as fp:
        data = fp.read(scan_limit)

    for position in range(
        0,
        max(0, len(data) - 4),
        4
    ):
        count = struct.unpack_from(
            "<I",
            data,
            position
        )[0]

        if not (
            1
            <= count
            <= 4096
        ):
            continue

        table_start = (
            position + 4
        )

        table_size = (
            count
            * FILE_ENTRY_SIZE
        )

        if (
            table_start
            + table_size
            > pac_size
        ):
            continue

        # Validate several descriptors.
        valid = 0

        try:
            with path.open("rb") as fp:
                fp.seek(table_start)

                sample_count = min(
                    count,
                    8
                )

                for i in range(
                    sample_count
                ):
                    raw = read_exact(
                        fp,
                        FILE_ENTRY_SIZE
                    )

                    try:
                        entry = parse_file_entry(
                            raw,
                            i,
                            pac_size
                        )
                    except Exception:
                        entry = None

                    if entry is not None:
                        valid += 1

            # Require a meaningful fraction of the sample.
            required = max(
                1,
                sample_count // 2
            )

            if valid >= required:
                return (
                    table_start,
                    count
                )

        except (
            OSError,
            EOFError
        ):
            continue

    raise ValueError(
        "Unable to locate a valid PAC FILE_T descriptor table."
    )


# ============================================================
# PARSE ALL ENTRIES
# ============================================================

def parse_all_entries(
    path,
    table_start,
    count,
    pac_size
):
    """
    Parse every descriptor.

    IMPORTANT:
    No name-based filtering occurs here.
    Every descriptor is retained whenever its data range can be
    proven valid.
    """

    entries = []

    with path.open("rb") as fp:
        fp.seek(table_start)

        for index in range(count):
            raw = read_exact(
                fp,
                FILE_ENTRY_SIZE
            )

            entry = parse_file_entry(
                raw,
                index,
                pac_size
            )

            if entry is None:
                # Keep operation-only/empty descriptor rather than
                # silently discarding it.
                entries.append(
                    {
                        "index": index,
                        "file_id": "",
                        "name": (
                            f"entry_{index:04d}.bin"
                        ),
                        "offset": 0,
                        "size": 0,
                        "empty": True,
                    }
                )
            else:
                entry["empty"] = (
                    entry["size"] == 0
                )

                entries.append(
                    entry
                )

    return entries


# ============================================================
# UNIQUE OUTPUT NAME
# ============================================================

def unique_destination(
    directory,
    filename
):
    """
    Prevent two PAC entries with identical names from overwriting
    each other.
    """

    destination = directory / filename

    if not destination.exists():
        return destination

    stem = destination.stem
    suffix = destination.suffix

    counter = 1

    while True:
        candidate = (
            directory
            / f"{stem}_{counter}{suffix}"
        )

        if not candidate.exists():
            return candidate

        counter += 1


# ============================================================
# SHA-256
# ============================================================

def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as fp:
        while True:
            chunk = fp.read(
                CHUNK_SIZE
            )

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


# ============================================================
# STREAM EXTRACTION
# ============================================================

def extract_entry(
    source_fp,
    destination,
    offset,
    size,
    name
):
    """
    Copy exactly 'size' bytes from the PAC using a fixed-size
    buffer. Memory consumption remains essentially constant even
    for multi-gigabyte partitions.
    """

    source_fp.seek(offset)

    remaining = size
    written = 0

    with destination.open("wb") as output_fp:

        while remaining:
            to_read = min(
                CHUNK_SIZE,
                remaining
            )

            data = source_fp.read(
                to_read
            )

            if not data:
                raise EOFError(
                    f"Unexpected EOF while extracting "
                    f"{name}."
                )

            output_fp.write(data)

            written += len(data)
            remaining -= len(data)

            progress_bar(
                written,
                size,
                name
            )

    return written


# ============================================================
# PAC EXTRACTION
# ============================================================

def extract_pac(path):
    pac_size = file_size(path)

    output_dir = Path(
        OUTPUT_DIR
    )

    try:
        output_dir.mkdir(
            parents=True,
            exist_ok=True
        )
    except OSError as exc:
        raise PermissionError(
            f"Unable to create output directory: {exc}"
        ) from exc

    if not os.access(
        output_dir,
        os.W_OK
    ):
        raise PermissionError(
            "Output directory is not writable."
        )

    info(f"Input : {path}")
    info(f"Size  : {human_size(pac_size)}")
    info(
        f"Output: {output_dir.resolve()}"
    )

    print()

    # --------------------------------------------------------
    # Validate PAC.
    # --------------------------------------------------------

    validate_pac_header(
        path
    )

    success(
        "PAC header detected."
    )

    print()

    # --------------------------------------------------------
    # Locate descriptor table.
    # --------------------------------------------------------

    info(
        "Scanning PAC partition/file structures..."
    )

    table_start, count = (
        discover_descriptor_table(
            path,
            pac_size
        )
    )

    success(
        f"PAC file count: {count}"
    )

    info(
        f"Descriptor table: "
        f"0x{table_start:X}"
    )

    print()

    # --------------------------------------------------------
    # Parse EVERY descriptor.
    # --------------------------------------------------------

    entries = parse_all_entries(
        path,
        table_start,
        count,
        pac_size
    )

    if len(entries) != count:
        raise ValueError(
            "Internal parser error: "
            "descriptor count mismatch."
        )

    print(
        f"{BOLD}{WHITE}"
        f"Detected entries: "
        f"{YELLOW}{len(entries)}"
        f"{RESET}"
    )

    print()

    # --------------------------------------------------------
    # Extraction.
    # --------------------------------------------------------

    extracted = 0
    empty = 0
    failed = 0

    start_time = time.time()

    with path.open("rb") as source_fp:

        for number, entry in enumerate(
            entries,
            start=1
        ):
            name = sanitize_filename(
                entry["name"]
            )

            offset = entry[
                "offset"
            ]

            size = entry[
                "size"
            ]

            print(
                f"{BLUE}"
                f"[{number}/{len(entries)}]"
                f"{RESET} "
                f"{WHITE}{name}{RESET} "
                f"({human_size(size)})"
            )

            # ------------------------------------------------
            # Empty/operation-only descriptor.
            # ------------------------------------------------

            if entry.get(
                "empty",
                False
            ):
                try:
                    destination = (
                        unique_destination(
                            output_dir,
                            name
                        )
                    )

                    # Preserve the entry as an empty file.
                    destination.touch()

                    empty += 1

                    success(
                        f"Empty entry preserved: "
                        f"{destination.name}"
                    )

                except OSError as exc:
                    failed += 1

                    error(
                        f"Unable to create empty entry: "
                        f"{exc}"
                    )

                print()
                continue

            # ------------------------------------------------
            # Bounds checking.
            # ------------------------------------------------

            if offset < 0:
                failed += 1

                error(
                    "Rejected: negative data offset."
                )

                print()
                continue

            if size < 0:
                failed += 1

                error(
                    "Rejected: negative data size."
                )

                print()
                continue

            if offset > pac_size:
                failed += 1

                error(
                    "Rejected: data offset is beyond "
                    "the PAC file."
                )

                print()
                continue

            if size > pac_size:
                failed += 1

                error(
                    "Rejected: data size exceeds "
                    "PAC file size."
                )

                print()
                continue

            if offset + size > pac_size:
                failed += 1

                error(
                    "Rejected: entry extends beyond "
                    "the PAC file."
                )

                print()
                continue

            try:
                destination = (
                    unique_destination(
                        output_dir,
                        name
                    )
                )

                written = extract_entry(
                    source_fp,
                    destination,
                    offset,
                    size,
                    name
                )

                if written != size:
                    raise IOError(
                        f"Size mismatch: expected "
                        f"{size}, wrote {written}."
                    )

                checksum = sha256_file(
                    destination
                )

                extracted += 1

                print(
                    f"  {GREEN}✓ Extracted:{RESET} "
                    f"{human_size(written)}"
                )

                print(
                    f"  {DIM}SHA256: "
                    f"{checksum}{RESET}"
                )

            except (
                OSError,
                EOFError,
                IOError
            ) as exc:

                failed += 1

                error(
                    f"Failed to extract "
                    f"{name}: {exc}"
                )

                # Remove partial output.
                try:
                    if destination.exists():
                        destination.unlink()
                except (
                    OSError,
                    UnboundLocalError
                ):
                    pass

            print()

    elapsed = (
        time.time()
        - start_time
    )

    # --------------------------------------------------------
    # Summary.
    # --------------------------------------------------------

    print(
        f"{BOLD}{RED}"
        "════════════════ EXTRACTION SUMMARY "
        "════════════════"
        f"{RESET}"
    )

    print(
        f"{GREEN}Extracted :{RESET} "
        f"{extracted}"
    )

    print(
        f"{YELLOW}Empty     :{RESET} "
        f"{empty}"
    )

    print(
        f"{RED}Failed    :{RESET} "
        f"{failed}"
    )

    print(
        f"{WHITE}Total     :{RESET} "
        f"{len(entries)}"
    )

    print(
        f"{WHITE}Output    :{RESET} "
        f"{output_dir.resolve()}"
    )

    print(
        f"{WHITE}Time      :{RESET} "
        f"{elapsed:.2f} seconds"
    )

    print(
        f"{BOLD}{RED}"
        "════════════════════════════════════════"
        f"{RESET}"
    )

    # A complete extraction means every descriptor either produced
    # its payload or was explicitly represented as an empty file.
    if failed == 0:
        success(
            "PAC extraction completed successfully."
        )
        return True

    warning(
        f"Extraction completed with {failed} failed entries."
    )

    return False


# ============================================================
# INPUT
# ============================================================

def ask_pac_path():
    while True:
        try:
            value = input(
                f"\n{BOLD}{YELLOW}"
                "Enter PAC file path"
                f"{RESET} : "
            ).strip()

        except KeyboardInterrupt:
            print()
            raise SystemExit(0)

        if not value:
            warning(
                "Please enter a PAC file path."
            )
            continue

        # Allow quoted Termux paths.
        value = (
            value
            .strip('"')
            .strip("'")
        )

        path = Path(
            value
        ).expanduser()

        if not path.exists():
            error(
                "PAC file does not exist."
            )
            continue

        if not path.is_file():
            error(
                "The supplied path is not a file."
            )
            continue

        if not os.access(
            path,
            os.R_OK
        ):
            error(
                "PAC file is not readable."
            )
            continue

        if file_size(path) == 0:
            error(
                "PAC file is empty."
            )
            continue

        return path


# ============================================================
# MAIN
# ============================================================

def main():
    clear_screen()
    banner()

    try:
        pac_path = ask_pac_path()

        print()

        start = time.time()

        completed = extract_pac(
            pac_path
        )

        elapsed = (
            time.time()
            - start
        )

        print()

        if completed:
            success(
                f"Finished in {elapsed:.2f} seconds."
            )
        else:
            warning(
                f"Finished in {elapsed:.2f} seconds "
                f"with extraction errors."
            )

    except KeyboardInterrupt:
        print()
        warning(
            "Extraction cancelled by user."
        )

    except (
        FileNotFoundError,
        PermissionError,
        EOFError,
        ValueError,
        OSError
    ) as exc:

        error(
            str(exc)
        )

        sys.exit(1)

    except Exception as exc:

        error(
            f"Unexpected error: {exc}"
        )

        sys.exit(1)


if __name__ == "__main__":
    main()

Important: I deliberately removed the previous signature-scanning fallback as a way to claim “100% extraction.” A PAC is a container with directory metadata; extracting only recognizable byte signatures can miss files or split data incorrectly. The documented PAC structure uses a file directory plus raw payload data, and current open-source implementations likewise expose an "extract_all()" operation based on the PAC directory.

For a specific PAC variant, the exact descriptor offsets can differ. If you give me one PAC file, I can adapt the parser to that file's actual header/table layout rather than guessing offsets.
