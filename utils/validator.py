"""
File‑upload validation helpers.
"""

import logging
import os

logger = logging.getLogger(__name__)

# Map of common magic bytes → human‑readable type
MAGIC_SIGNATURES: dict[bytes, str] = {
    b"MZ": "PE executable",
    b"\x7fELF": "ELF binary",
    b"PK": "ZIP / DOCX / JAR archive",
    b"\x1f\x8b": "gzip archive",
    b"MDMP": "Windows minidump",
    b"\x89PNG": "PNG image",
}


def detect_file_type(filepath: str) -> str:
    """Return a best‑effort file‑type string based on magic bytes."""
    try:
        with open(filepath, "rb") as fh:
            header = fh.read(8)
    except OSError:
        return "unknown"

    for magic, label in MAGIC_SIGNATURES.items():
        if header[: len(magic)] == magic:
            return label
    return "unknown"


def validate_upload(filepath: str, accepted_extensions: list[str]) -> tuple[bool, str]:
    """Validate that *filepath* exists and has an accepted extension.

    Returns ``(ok, message)``.
    """
    if not os.path.isfile(filepath):
        return False, "Uploaded file not found on disk."

    ext = os.path.splitext(filepath)[1].lower()
    if accepted_extensions and ext not in accepted_extensions:
        return False, (
            f"File extension '{ext}' is not accepted. "
            f"Accepted: {', '.join(accepted_extensions)}"
        )

    size = os.path.getsize(filepath)
    if size == 0:
        return False, "Uploaded file is empty."

    file_type = detect_file_type(filepath)
    logger.info("Validated %s — type=%s, size=%d bytes", filepath, file_type, size)
    return True, f"File OK ({file_type}, {size:,} bytes)"
