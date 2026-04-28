"""CMS / CAdES verification tests."""
from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from sigillum.cms import (
    build_chain,
    check_message_digest,
    find_signer_cert,
    get_payload,
    is_pdf,
    load_p7m,
    looks_like_cms,
    verify_chain_signatures,
    verify_sig,
)
from sigillum.tsl import verify_against_tsl


def _signer_setup(p7m: bytes):
    ci = load_p7m(p7m)
    sd = ci["content"]
    si = sd["signer_infos"][0]
    asn1_cert, _all = find_signer_cert(sd, si)
    cert = x509.load_der_x509_certificate(asn1_cert.dump())
    payload = get_payload(sd)
    return sd, si, cert, payload


def test_good_signature_verifies(p7m_bytes):
    p7m, _payload, _cert = p7m_bytes
    sd, si, cert, payload = _signer_setup(p7m)
    assert verify_sig(cert, si, payload) is True
    assert check_message_digest(si, payload) is True


def test_bad_signature_detected_via_digest(p7m_bytes):
    p7m, _payload, _cert = p7m_bytes
    sd, si, cert, payload = _signer_setup(p7m)
    mutated = bytearray(payload)
    mutated[0] ^= 0x01
    assert check_message_digest(si, bytes(mutated)) is False


def test_looks_like_cms_on_renamed_pdf(p7m_bytes):
    """Filename irrelevant: detection is by content."""
    p7m, _payload, _cert = p7m_bytes
    assert looks_like_cms(p7m) is True


def test_pdf_rejected(pdf_bytes):
    assert is_pdf(pdf_bytes) is True
    assert looks_like_cms(pdf_bytes) is False


def test_chain_of_one_self_signed(p7m_bytes):
    p7m, _payload, _cert = p7m_bytes
    sd, _si, signer_cert, _payload2 = _signer_setup(p7m)
    signer_der = signer_cert.public_bytes(serialization.Encoding.DER)
    all_der = [c.chosen.dump() for c in sd["certificates"] if c.name == "certificate"]
    chain = build_chain(signer_der, all_der)
    assert len(chain) == 1
    assert chain[0].subject == chain[0].issuer
    ok, err = verify_chain_signatures(chain)
    assert ok is True and err is None


def test_tsl_anchor_present(p7m_bytes, self_signed):
    _key, cert = self_signed
    p7m, _payload, _c = p7m_bytes
    sd, _si, signer_cert, _p = _signer_setup(p7m)
    signer_der = signer_cert.public_bytes(serialization.Encoding.DER)
    all_der = [c.chosen.dump() for c in sd["certificates"] if c.name == "certificate"]
    chain = build_chain(signer_der, all_der)
    status, anchor = verify_against_tsl(chain, [cert])
    assert status == "trusted"
    assert anchor.public_bytes(serialization.Encoding.DER) == cert.public_bytes(
        serialization.Encoding.DER
    )


def test_tsl_anchor_missing(p7m_bytes):
    p7m, _payload, _cert = p7m_bytes
    sd, _si, signer_cert, _p = _signer_setup(p7m)
    signer_der = signer_cert.public_bytes(serialization.Encoding.DER)
    all_der = [c.chosen.dump() for c in sd["certificates"] if c.name == "certificate"]
    chain = build_chain(signer_der, all_der)
    status, anchor = verify_against_tsl(chain, [])
    assert status == "untrusted"
    assert anchor is None
