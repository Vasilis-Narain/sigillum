"""Fixtures for CMS/CAdES tests. No real fiscal codes or personal data."""
from __future__ import annotations

import datetime as _dt
import hashlib

import pytest
from asn1crypto import algos, cms, core
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


def _build_p7m(payload: bytes, key, cert) -> bytes:
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

    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": sid,
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signed_attrs": signed_attrs,
        "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "rsassa_pkcs1v15"}),
        "signature": signature,
    })

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
def pdf_bytes():
    return b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj <<>>\nendobj\n%%EOF\n"
