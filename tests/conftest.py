"""Fixtures for CMS/CAdES tests. No real fiscal codes or personal data."""
from __future__ import annotations

import datetime as _dt
import hashlib

import pytest
from asn1crypto import algos, cms, core, tsp
from asn1crypto import x509 as a_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID


def _make_self_signed():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.COMMON_NAME, "sigillum-test"),
    ])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(0x1234)
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _build_tst(outer_sig_value: bytes, key, cert,
               imprint_algo: str = "sha256",
               tamper_imprint: bool = False) -> bytes:
    """Build a minimal RFC 3161 TimeStampToken (CMS SignedData wrapping TSTInfo)."""
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    a_cert = a_x509.Certificate.load(cert_der)

    h_map = {"sha1": hashlib.sha1, "sha256": hashlib.sha256,
             "sha384": hashlib.sha384, "sha512": hashlib.sha512}
    digest_outer = h_map[imprint_algo](outer_sig_value).digest()
    if tamper_imprint:
        digest_outer = bytes(b ^ 0xFF for b in digest_outer)

    gen_time = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    tst_info = tsp.TSTInfo({
        "version": "v1",
        "policy": "1.2.3.4.5",
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": imprint_algo}),
            "hashed_message": digest_outer,
        }),
        "serial_number": 1,
        "gen_time": gen_time,
    })
    tst_info_der = tst_info.dump()

    md = hashlib.sha256(tst_info_der).digest()
    signing_time = gen_time
    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({"type": "content_type",
                          "values": [cms.ContentType("tst_info")]}),
        cms.CMSAttribute({"type": "signing_time",
                          "values": [cms.Time({"utc_time": core.UTCTime(signing_time)})]}),
        cms.CMSAttribute({"type": "message_digest",
                          "values": [core.OctetString(md)]}),
    ])
    to_sign = signed_attrs.dump()
    to_sign = b"\x31" + to_sign[1:]
    signature = key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())

    sid = cms.SignerIdentifier({
        "issuer_and_serial_number": cms.IssuerAndSerialNumber({
            "issuer": a_cert.issuer,
            "serial_number": a_cert.serial_number,
        }),
    })
    si = cms.SignerInfo({
        "version": "v1",
        "sid": sid,
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signed_attrs": signed_attrs,
        "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "rsassa_pkcs1v15"}),
        "signature": signature,
    })
    sd = cms.SignedData({
        "version": "v3",
        "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
        "encap_content_info": {
            "content_type": "tst_info",
            "content": tst_info,
        },
        "certificates": [cms.CertificateChoices({"certificate": a_cert})],
        "signer_infos": [si],
    })
    ci = cms.ContentInfo({"content_type": "signed_data", "content": sd})
    return ci.dump()


def _build_p7m(payload: bytes, key, cert, with_tst: bool = False,
               tst_tamper_imprint: bool = False) -> bytes:
    """Build minimal CMS SignedData (RSA-PKCS1v15-SHA256, embedded payload)."""
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    a_cert = a_x509.Certificate.load(cert_der)

    digest = hashlib.sha256(payload).digest()
    signing_time = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)

    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({
            "type": "content_type",
            "values": [cms.ContentType("data")],
        }),
        cms.CMSAttribute({
            "type": "signing_time",
            "values": [cms.Time({"utc_time": core.UTCTime(signing_time)})],
        }),
        cms.CMSAttribute({
            "type": "message_digest",
            "values": [core.OctetString(digest)],
        }),
    ])

    to_sign = signed_attrs.dump()  # SET OF (implicit [0] IMPLICIT in struct,
    # but for hashing we use explicit SET DER per RFC 5652 §5.4)
    # asn1crypto dumps the IMPLICIT [0] form; need explicit SET tag for signing.
    to_sign = b"\x31" + to_sign[1:]  # swap tag 0xA0 → 0x31 (SET)

    signature = key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())

    sid = cms.SignerIdentifier({
        "issuer_and_serial_number": cms.IssuerAndSerialNumber({
            "issuer": a_cert.issuer,
            "serial_number": a_cert.serial_number,
        }),
    })

    si_dict = {
        "version": "v1",
        "sid": sid,
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signed_attrs": signed_attrs,
        "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "rsassa_pkcs1v15"}),
        "signature": signature,
    }
    if with_tst:
        tst_der = _build_tst(signature, key, cert,
                             tamper_imprint=tst_tamper_imprint)
        si_dict["unsigned_attrs"] = cms.CMSAttributes([
            cms.CMSAttribute({
                "type": "signature_time_stamp_token",
                "values": [cms.ContentInfo.load(tst_der)],
            }),
        ])
    signer_info = cms.SignerInfo(si_dict)

    signed_data = cms.SignedData({
        "version": "v1",
        "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
        "encap_content_info": {
            "content_type": "data",
            "content": payload,
        },
        "certificates": [cms.CertificateChoices({"certificate": a_cert})],
        "signer_infos": [signer_info],
    })

    ci = cms.ContentInfo({
        "content_type": "signed_data",
        "content": signed_data,
    })
    return ci.dump()


@pytest.fixture
def self_signed():
    return _make_self_signed()


@pytest.fixture
def p7m_bytes(self_signed):
    key, cert = self_signed
    payload = b"hello sigillum test payload"
    return _build_p7m(payload, key, cert), payload, cert


@pytest.fixture
def p7m_with_tst(self_signed):
    key, cert = self_signed
    payload = b"timestamped payload"
    return _build_p7m(payload, key, cert, with_tst=True), payload, cert


@pytest.fixture
def p7m_with_bad_tst(self_signed):
    key, cert = self_signed
    payload = b"tampered tst payload"
    return _build_p7m(payload, key, cert, with_tst=True,
                      tst_tamper_imprint=True), payload, cert


@pytest.fixture
def pdf_bytes():
    return b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj <<>>\nendobj\n%%EOF\n"
