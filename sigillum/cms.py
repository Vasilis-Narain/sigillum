"""CMS SignedData parsing + signer/chain verification (CAdES-friendly)."""
from __future__ import annotations

import base64
import hashlib
from datetime import timezone

from asn1crypto import cms
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


HASH_MAP = {
    "sha1": hashes.SHA1, "sha224": hashes.SHA224,
    "sha256": hashes.SHA256, "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}
HASHLIB_MAP = {
    "sha1": hashlib.sha1, "sha224": hashlib.sha224,
    "sha256": hashlib.sha256, "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


# ── Sniffing ─────────────────────────────────────────────────────────────────

def looks_like_cms(data: bytes) -> bool:
    """Heuristic: bytes look like CMS (DER) or base64-armored CMS."""
    if data[:1] == b"\x30":
        return True
    head = data.lstrip()[:64]
    try:
        decoded = base64.b64decode(head + b"=" * (-len(head) % 4), validate=False)
        return decoded[:1] == b"\x30"
    except Exception:
        return False


def is_pdf(data: bytes) -> bool:
    return data[:4] == b"%PDF"


# ── Loading ──────────────────────────────────────────────────────────────────

def load_p7m(data: bytes) -> cms.ContentInfo:
    if data[:1] != b"\x30":
        try:
            data = base64.b64decode(data, validate=False)
        except Exception:
            pass
    return cms.ContentInfo.load(data)


def get_payload(signed_data) -> bytes:
    encap = signed_data["encap_content_info"]
    content = encap["content"]
    if content is None:
        raise ValueError("Detached signature, payload not embedded.")
    return content.native


# ── Cert helpers ─────────────────────────────────────────────────────────────

def cert_validity(cert):
    """Aware UTC (nb, na) across cryptography versions."""
    nb = getattr(cert, "not_valid_before_utc", None)
    na = getattr(cert, "not_valid_after_utc", None)
    if nb is None:
        nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
        na = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return nb, na


def verify_cert_signed_by(child, parent) -> bool:
    parent_pub = parent.public_key()
    sh = child.signature_hash_algorithm
    try:
        if isinstance(parent_pub, rsa.RSAPublicKey):
            parent_pub.verify(child.signature, child.tbs_certificate_bytes,
                              padding.PKCS1v15(), sh)
        elif isinstance(parent_pub, ec.EllipticCurvePublicKey):
            parent_pub.verify(child.signature, child.tbs_certificate_bytes,
                              ec.ECDSA(sh))
        else:
            return False
        return True
    except InvalidSignature:
        return False


# ── Signer + signature verification ──────────────────────────────────────────

def find_signer_cert(signed_data, signer_info):
    sid = signer_info["sid"]
    certs = [c.chosen for c in signed_data["certificates"] if c.name == "certificate"]
    for c in certs:
        if sid.name == "issuer_and_serial_number":
            if (c.issuer == sid.chosen["issuer"]
                    and c.serial_number == sid.chosen["serial_number"].native):
                return c, certs
        else:
            if c.key_identifier == sid.chosen.native:
                return c, certs
    raise LookupError("Signer cert not found in bundle.")


def verify_sig(cert, signer_info, payload: bytes) -> bool:
    pubkey = cert.public_key()
    digest_algo = signer_info["digest_algorithm"]["algorithm"].native
    hash_cls = HASH_MAP[digest_algo]

    signed_attrs = signer_info["signed_attrs"]
    if signed_attrs.native is not None:
        signed_bytes = signed_attrs.retag(17).dump()
    else:
        signed_bytes = payload

    sig = signer_info["signature"].native
    try:
        if isinstance(pubkey, rsa.RSAPublicKey):
            pubkey.verify(sig, signed_bytes, padding.PKCS1v15(), hash_cls())
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            pubkey.verify(sig, signed_bytes, ec.ECDSA(hash_cls()))
        else:
            raise ValueError(f"Unsupported key type: {type(pubkey).__name__}")
        return True
    except InvalidSignature:
        return False


# ── Signed attributes ────────────────────────────────────────────────────────

def get_signed_attr(signer_info, oid: str):
    sa = signer_info["signed_attrs"]
    if sa.native is None:
        return None
    for attr in sa:
        if attr["type"].native == oid:
            return attr["values"][0]
    return None


def check_message_digest(signer_info, payload: bytes):
    md_attr = get_signed_attr(signer_info, "message_digest")
    if md_attr is None:
        return None
    digest_algo = signer_info["digest_algorithm"]["algorithm"].native
    h = HASHLIB_MAP[digest_algo](payload).digest()
    return h == md_attr.native


def check_content_type(signer_info, signed_data):
    ct_attr = get_signed_attr(signer_info, "content_type")
    if ct_attr is None:
        return None
    return ct_attr.native == signed_data["encap_content_info"]["content_type"].native


def get_signing_time(signer_info):
    st = get_signed_attr(signer_info, "signing_time")
    if st is None:
        return None
    val = st.native
    if val.tzinfo is None:
        val = val.replace(tzinfo=timezone.utc)
    return val


def check_eku(cert) -> list[str]:
    notes: list[str] = []
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not (ku.digital_signature or ku.content_commitment):
            notes.append("KeyUsage lacks digitalSignature/nonRepudiation")
    except x509.ExtensionNotFound:
        notes.append("KeyUsage absent")
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        ok_ekus = {x509.ExtendedKeyUsageOID.EMAIL_PROTECTION,
                   x509.ExtendedKeyUsageOID.CODE_SIGNING,
                   x509.ExtendedKeyUsageOID.CLIENT_AUTH}
        if not any(o in ok_ekus for o in eku):
            notes.append(f"EKU={[o.dotted_string for o in eku]}")
    except x509.ExtensionNotFound:
        pass
    return notes


# ── Chain ────────────────────────────────────────────────────────────────────

def _der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def build_chain(signer_der: bytes, all_certs_der: list[bytes]):
    bundle = [x509.load_der_x509_certificate(d) for d in all_certs_der]
    signer = x509.load_der_x509_certificate(signer_der)
    chain = [signer]
    seen = {_der(signer)}
    cur = signer
    while cur.issuer != cur.subject:
        nxt = next((c for c in bundle if c.subject == cur.issuer), None)
        if nxt is None or _der(nxt) in seen:
            break
        chain.append(nxt)
        seen.add(_der(nxt))
        cur = nxt
    return chain


def verify_chain_signatures(chain) -> tuple[bool, str | None]:
    for i in range(len(chain) - 1):
        if not verify_cert_signed_by(chain[i], chain[i + 1]):
            return False, f"Bad signature at link {i}"
    return True, None
