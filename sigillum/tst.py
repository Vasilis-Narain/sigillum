"""RFC 3161 SignatureTimeStampToken parsing + verification."""
from __future__ import annotations

from datetime import timezone

from asn1crypto import cms as a_cms
from asn1crypto import tsp
from cryptography import x509

from sigillum.cms import (
    HASHLIB_MAP,
    build_chain,
    check_message_digest,
    find_signer_cert,
    verify_chain_signatures,
    verify_sig,
)

TST_OID = "1.2.840.113549.1.9.16.2.14"  # id-aa-signatureTimeStampToken


def extract_signature_timestamp(signer_info) -> bytes | None:
    """Return DER bytes of the TimeStampToken (CMS ContentInfo) or None."""
    ua = signer_info["unsigned_attrs"]
    if ua.native is None:
        return None
    for attr in ua:
        if attr["type"].dotted == TST_OID:
            v = attr["values"][0]
            # Value is a ContentInfo (TimeStampToken). Get its DER.
            return v.dump() if not isinstance(v, (bytes, bytearray)) else bytes(v)
    return None


def parse_tst(der: bytes) -> dict:
    """Parse a TimeStampToken DER. Returns dict with ci, sd, signer_info, tst_info, tst_info_der."""
    ci = a_cms.ContentInfo.load(der)
    if ci["content_type"].native != "signed_data":
        raise ValueError("TimeStampToken is not signed_data")
    sd = ci["content"]
    if not len(sd["signer_infos"]):
        raise ValueError("TimeStampToken has no signer_infos")
    si = sd["signer_infos"][0]
    eci = sd["encap_content_info"]
    ct = eci["content_type"].native
    if ct != "tst_info":
        raise ValueError(f"TimeStampToken eContentType is {ct}, expected tst_info")
    # OCTET STRING contents = inner DER of TSTInfo
    tst_info_der = eci["content"].contents
    tst_info = tsp.TSTInfo.load(tst_info_der)
    return {
        "ci": ci,
        "sd": sd,
        "signer_info": si,
        "tst_info": tst_info,
        "tst_info_der": tst_info_der,
    }


def verify_tst(tst: dict, outer_signature_value: bytes) -> dict:
    """Verify a parsed TST against the outer SignerInfo's signature value.

    Returns dict with sig_ok, md_ok, imprint_ok, gen_time, chain, chain_ok,
    chain_err, tsa_cert, error.
    """
    out = {
        "sig_ok": False, "md_ok": None, "imprint_ok": False,
        "gen_time": None, "chain": [], "chain_ok": False, "chain_err": None,
        "tsa_cert": None, "error": None,
    }
    try:
        sd = tst["sd"]
        si = tst["signer_info"]
        tst_info = tst["tst_info"]
        tst_info_der = tst["tst_info_der"]

        signer_asn1, all_asn1 = find_signer_cert(sd, si)
        tsa_cert = x509.load_der_x509_certificate(signer_asn1.dump())
        out["tsa_cert"] = tsa_cert

        # Signature math: verify_sig hashes signed_attrs when present (RFC 5652 §5.4).
        # The payload arg is unused when signed_attrs are present, but pass tst_info_der for safety.
        out["sig_ok"] = verify_sig(tsa_cert, si, tst_info_der)
        out["md_ok"] = check_message_digest(si, tst_info_der)

        imp = tst_info["message_imprint"]
        algo = imp["hash_algorithm"]["algorithm"].native
        if algo not in HASHLIB_MAP:
            raise ValueError(f"Unsupported imprint hash: {algo}")
        expected = imp["hashed_message"].native
        actual = HASHLIB_MAP[algo](outer_signature_value).digest()
        out["imprint_ok"] = (expected == actual)

        gt = tst_info["gen_time"].native
        if gt.tzinfo is None:
            gt = gt.replace(tzinfo=timezone.utc)
        out["gen_time"] = gt

        chain = build_chain(signer_asn1.dump(), [c.dump() for c in all_asn1])
        out["chain"] = chain
        out["chain_ok"], out["chain_err"] = verify_chain_signatures(chain)
    except Exception as e:
        out["error"] = str(e)
    return out
