#!/usr/bin/env python3

import argparse
import hashlib
import math
from pathlib import Path

import pefile


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a byte sequence."""
    if not data:
        return 0.0

    counts = [0] * 256

    for byte in data:
        counts[byte] += 1

    length = len(data)
    entropy = 0.0

    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)

    return entropy


def sha256_file(path: Path) -> str:
    """Calculate SHA-256 of a file."""
    digest = hashlib.sha256()

    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def section_characteristics(section):
    """Extract executable/readable/writable section flags."""
    characteristics = section.Characteristics

    return {
        "executable": int(bool(characteristics & 0x20000000)),
        "readable": int(bool(characteristics & 0x40000000)),
        "writable": int(bool(characteristics & 0x80000000)),
    }


def decode_bytes(value):
    """Safely decode PE byte strings."""
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip().lower()

    return str(value).strip().lower()


# ---------------------------------------------------------------------------
# PE feature extraction
# ---------------------------------------------------------------------------

def extract_features(path: Path) -> dict:
    """Extract static PE features from one malware sample."""

    path = Path(path)

    if not path.is_file():
        raise FileNotFoundError(f"Sample not found: {path}")

    if path.stat().st_size == 0:
        raise ValueError("Sample is zero bytes")

    # -----------------------------------------------------------------------
    # File identity
    # -----------------------------------------------------------------------

    result = {
        "sha256": sha256_file(path),
        "file_size": path.stat().st_size,
    }

    # -----------------------------------------------------------------------
    # PE parsing
    # -----------------------------------------------------------------------

    pe = pefile.PE(str(path), fast_load=False)

    try:

        # -------------------------------------------------------------------
        # PE header
        # -------------------------------------------------------------------

        result.update({
            "machine": pe.FILE_HEADER.Machine,
            "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "characteristics": pe.FILE_HEADER.Characteristics,
            "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "image_base": pe.OPTIONAL_HEADER.ImageBase,
            "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
            "size_of_headers": pe.OPTIONAL_HEADER.SizeOfHeaders,
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "dll_characteristics": (
                pe.OPTIONAL_HEADER.DllCharacteristics
            ),
        })

        # -------------------------------------------------------------------
        # Architecture
        # -------------------------------------------------------------------

        if pe.FILE_HEADER.Machine == 0x14C:
            result["architecture"] = "x86"

        elif pe.FILE_HEADER.Machine == 0x8664:
            result["architecture"] = "x64"

        elif pe.FILE_HEADER.Machine == 0xAA64:
            result["architecture"] = "ARM64"

        else:
            result["architecture"] = "other"

        # -------------------------------------------------------------------
        # Sections
        # -------------------------------------------------------------------

        entropies = []

        executable_sections = 0
        readable_sections = 0
        writable_sections = 0

        total_raw_section_size = 0
        total_virtual_section_size = 0

        for section in pe.sections:

            try:
                section_data = section.get_data()
            except Exception:
                section_data = b""

            entropies.append(
                shannon_entropy(section_data)
            )

            flags = section_characteristics(section)

            executable_sections += flags["executable"]
            readable_sections += flags["readable"]
            writable_sections += flags["writable"]

            total_raw_section_size += section.SizeOfRawData
            total_virtual_section_size += section.Misc_VirtualSize

        result.update({
            "executable_sections": executable_sections,
            "readable_sections": readable_sections,
            "writable_sections": writable_sections,
            "total_raw_section_size": total_raw_section_size,
            "total_virtual_section_size": total_virtual_section_size,
            "mean_section_entropy": (
                sum(entropies) / len(entropies)
                if entropies else 0.0
            ),
            "min_section_entropy": (
                min(entropies)
                if entropies else 0.0
            ),
            "max_section_entropy": (
                max(entropies)
                if entropies else 0.0
            ),
        })

        # -------------------------------------------------------------------
        # Imports
        # -------------------------------------------------------------------

        imported_dlls = set()
        imported_apis = set()

        imported_dll_count = 0
        imported_api_count = 0

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):

            for entry in pe.DIRECTORY_ENTRY_IMPORT:

                imported_dll_count += 1

                # DLL name
                dll_name = decode_bytes(entry.dll)

                if dll_name:
                    imported_dlls.add(dll_name)

                # API names
                for imported_function in entry.imports:

                    imported_api_count += 1

                    if imported_function.name:

                        api_name = decode_bytes(
                            imported_function.name
                        )

                        if api_name:
                            imported_apis.add(api_name)

        result.update({
            "imported_dll_count": imported_dll_count,
            "imported_api_count": imported_api_count,
            "unique_imported_api_count": len(imported_apis),

            # Reproducible categorical representations.
            # "|" is used as the token separator.
            "imported_dll_names": "|".join(
                sorted(imported_dlls)
            ),

            "imported_api_names": "|".join(
                sorted(imported_apis)
            ),
        })

    finally:
        pe.close()

    return result


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Extract static PE features from one malware sample."
    )

    parser.add_argument(
        "--sample",
        required=True,
        help="Path to one sample.bin",
    )

    parser.add_argument(
        "--expected-sha",
        required=False,
        help="Expected SHA-256 for integrity verification",
    )

    args = parser.parse_args()

    sample_path = Path(args.sample)

    try:
        features = extract_features(sample_path)

    except pefile.PEFormatError as exc:
        print("STATIC PE FEATURE EXTRACTION")
        print("=" * 60)
        print("STATUS : PE PARSE FAILED")
        print(f"ERROR  : {exc}")
        raise SystemExit(2)

    except Exception as exc:
        print("STATIC PE FEATURE EXTRACTION")
        print("=" * 60)
        print("STATUS : EXTRACTION FAILED")
        print(f"ERROR  : {exc}")
        raise SystemExit(3)

    # -----------------------------------------------------------------------
    # Output
    # -----------------------------------------------------------------------

    print("STATIC PE FEATURE EXTRACTION")
    print("=" * 60)

    for key, value in features.items():
        print(f"{key:<30}: {value}")

    # -----------------------------------------------------------------------
    # SHA verification
    # -----------------------------------------------------------------------

    if args.expected_sha:

        calculated = features["sha256"].lower()
        expected = args.expected_sha.lower()

        print()
        print(
            "SHA verification:",
            "PASS" if calculated == expected else "FAIL"
        )

        if calculated != expected:
            raise SystemExit(4)


if __name__ == "__main__":
    main()