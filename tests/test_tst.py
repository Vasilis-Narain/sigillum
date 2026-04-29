"""RFC 3161 SignatureTimeStampToken tests."""
from __future__ import annotations

from sigillum.cms import load_p7m
from sigillum.tst import (
    extract_signature_timestamp,
    parse_tst,
    verify_tst,
)


def _signer_info(p7m_bytes):
    ci = load_p7m(p7m_bytes)
    return ci["content"]["signer_infos"][0]


def test_extract_absent(p7m_bytes):
    p7m, _, _ = p7m_bytes
    assert extract_signature_timestamp(_signer_info(p7m)) is None


def test_extract_present(p7m_with_tst):
    p7m, _, _ = p7m_with_tst
    der = extract_signature_timestamp(_signer_info(p7m))
    assert der is not None
    assert der[:1] == b"\x30"  # SEQUENCE — looks like ContentInfo DER


def test_parse_tst_fields(p7m_with_tst):
    p7m, _, _ = p7m_with_tst
    si = _signer_info(p7m)
    tst = parse_tst(extract_signature_timestamp(si))
    assert tst["tst_info"]["version"].native == "v1"
    assert tst["tst_info"]["gen_time"].native is not None


def test_verify_tst_valid(p7m_with_tst):
    p7m, _, _ = p7m_with_tst
    si = _signer_info(p7m)
    tst = parse_tst(extract_signature_timestamp(si))
    res = verify_tst(tst, si["signature"].native)
    assert res["sig_ok"] is True
    assert res["imprint_ok"] is True
    assert res["md_ok"] is True
    assert res["chain_ok"] is True
    assert res["gen_time"] is not None


def test_verify_tst_imprint_mismatch(p7m_with_bad_tst):
    p7m, _, _ = p7m_with_bad_tst
    si = _signer_info(p7m)
    tst = parse_tst(extract_signature_timestamp(si))
    res = verify_tst(tst, si["signature"].native)
    # Signature math + chain still valid; only imprint fails
    assert res["sig_ok"] is True
    assert res["imprint_ok"] is False


def test_verify_tst_imprint_mismatch_against_wrong_outer(p7m_with_tst):
    p7m, _, _ = p7m_with_tst
    si = _signer_info(p7m)
    tst = parse_tst(extract_signature_timestamp(si))
    res = verify_tst(tst, b"not the real outer signature")
    assert res["imprint_ok"] is False
