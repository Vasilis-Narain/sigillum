"""PAdES support tests: extract & verify CMS embedded in PDF."""
from __future__ import annotations

from io import BytesIO

import pytest
from asn1crypto import keys as a_keys
from asn1crypto import x509 as a_x509
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.writer import PdfFileWriter
from pyhanko.sign import signers
from pyhanko_certvalidator.registry import SimpleCertificateStore

from sigillum.cms import (
    check_message_digest,
    find_signer_cert,
    load_p7m,
    verify_sig,
)
from sigillum.pades import (
    bytes_after_signature,
    coverage_complete,
    extract_pdf_signatures,
)


@pytest.fixture
def signed_pdf(self_signed):
    """Build a tiny single-page PDF and sign it with the self-signed cert."""
    key, cert = self_signed
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    key_der = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    a_cert = a_x509.Certificate.load(cert_der)
    a_key = a_keys.PrivateKeyInfo.load(key_der)

    registry = SimpleCertificateStore()
    registry.register(a_cert)
    signer = signers.SimpleSigner(
        signing_cert=a_cert,
        signing_key=a_key,
        cert_registry=registry,
    )

    blank = PdfFileWriter()
    page = generic.DictionaryObject({
        pdf_name("/Type"): pdf_name("/Page"),
        pdf_name("/MediaBox"): generic.ArrayObject(
            [generic.NumberObject(0)] * 2
            + [generic.NumberObject(612), generic.NumberObject(792)]
        ),
        pdf_name("/Resources"): generic.DictionaryObject(),
    })
    blank.insert_page(page)
    blank_buf = BytesIO()
    blank.write(blank_buf)
    blank_buf.seek(0)

    writer = IncrementalPdfFileWriter(blank_buf)
    meta = signers.PdfSignatureMetadata(field_name="Signature1")
    out = signers.sign_pdf(writer, signature_meta=meta, signer=signer)
    return out.getvalue()


def _verify_first_signature(pdf_bytes):
    sigs = extract_pdf_signatures(pdf_bytes)
    assert len(sigs) == 1
    sig = sigs[0]
    ci = load_p7m(sig.cms_bytes)
    sd = ci["content"]
    si = sd["signer_infos"][0]
    asn1_cert, _ = find_signer_cert(sd, si)
    cert = x509.load_der_x509_certificate(asn1_cert.dump())
    return sig, sd, si, cert


def test_extract_single_signature(signed_pdf):
    sigs = extract_pdf_signatures(signed_pdf)
    assert len(sigs) == 1
    sig = sigs[0]
    assert len(sig.byte_range) == 4
    assert sig.cms_bytes[:1] == b"\x30"  # CMS DER
    assert sig.total_len == len(signed_pdf)
    assert sig.field_name == "Signature1"


def test_pades_signature_verifies(signed_pdf):
    sig, _sd, si, cert = _verify_first_signature(signed_pdf)
    assert verify_sig(cert, si, sig.signed_bytes) is True
    assert check_message_digest(si, sig.signed_bytes) is True


def test_pades_bad_signature_detected(signed_pdf):
    sig, _sd, si, _cert = _verify_first_signature(signed_pdf)
    mutated = bytearray(sig.signed_bytes)
    mutated[10] ^= 0xFF
    assert check_message_digest(si, bytes(mutated)) is False


def test_full_coverage_clean_pdf(signed_pdf):
    sigs = extract_pdf_signatures(signed_pdf)
    sig = sigs[0]
    assert coverage_complete(sig.byte_range, sig.total_len) is True
    assert bytes_after_signature(sig.byte_range, sig.total_len) == 0


def test_cli_validates_signed_pdf(signed_pdf, tmp_path, capsys, monkeypatch):
    from sigillum.cli import main

    pdf_path = tmp_path / "signed.pdf"
    pdf_path.write_bytes(signed_pdf)
    with pytest.raises(SystemExit) as exc:
        main(["--no-tsl", "--no-open", "--quiet-on-valid", str(pdf_path)])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "VALID" in out


def test_incremental_update_detected(signed_pdf):
    appended = signed_pdf + b"\n%post-sign tampering\n"
    sigs = extract_pdf_signatures(appended)
    sig = sigs[0]
    assert coverage_complete(sig.byte_range, sig.total_len) is False
    assert bytes_after_signature(sig.byte_range, sig.total_len) == len(
        b"\n%post-sign tampering\n"
    )
