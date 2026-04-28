"""PAdES support: extract CMS signatures embedded in PDF /ByteRange + /Contents."""
from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO

from pyhanko.pdf_utils.reader import PdfFileReader


@dataclass
class PadesSig:
    """One embedded PDF signature, extracted to CAdES-friendly form."""

    field_name: str
    cms_bytes: bytes
    signed_bytes: bytes
    byte_range: tuple[int, int, int, int]
    total_len: int
    sig_object_type: str  # "/Sig" or "/DocTimeStamp"


def extract_pdf_signatures(data: bytes) -> list[PadesSig]:
    """Return all embedded signatures in the PDF, in signing order."""
    reader = PdfFileReader(BytesIO(data))
    out: list[PadesSig] = []
    total_len = len(data)
    for emb in reader.embedded_signatures:
        br = tuple(int(x) for x in emb.byte_range)
        if len(br) != 4:
            continue
        a, b, c, d = br
        signed_bytes = data[a : a + b] + data[c : c + d]
        out.append(
            PadesSig(
                field_name=emb.field_name,
                cms_bytes=bytes(emb.pkcs7_content),
                signed_bytes=signed_bytes,
                byte_range=(a, b, c, d),
                total_len=total_len,
                sig_object_type=str(emb.sig_object_type),
            )
        )
    return out


def coverage_complete(byte_range: tuple[int, int, int, int], total_len: int) -> bool:
    """ByteRange covers the entire file save for the /Contents hex slot."""
    a, _b, c, d = byte_range
    return a == 0 and (c + d) == total_len


def bytes_after_signature(byte_range: tuple[int, int, int, int], total_len: int) -> int:
    """Bytes appended after the signed region (incremental update indicator)."""
    _a, _b, c, d = byte_range
    tail = total_len - (c + d)
    return tail if tail > 0 else 0
