"""eIDAS Trust Service List (TSL) anchor verification."""
from __future__ import annotations

import base64
import os
import time
import urllib.request
import xml.etree.ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from sigillum.cms import verify_cert_signed_by

TSL_URL_IT = "https://eidas.agid.gov.it/TL/TSL-IT.xml"
TSL_CACHE_DIR = os.path.expanduser("~/.cache/sigillum")
TSL_CACHE = os.path.join(TSL_CACHE_DIR, "TSL-IT.xml")
TSL_MAX_AGE = 7 * 86400  # one week


def fetch_tsl(url: str = TSL_URL_IT, cache: str = TSL_CACHE,
              max_age: int = TSL_MAX_AGE) -> bytes:
    os.makedirs(os.path.dirname(cache), exist_ok=True)
    if os.path.exists(cache) and (time.time() - os.path.getmtime(cache) < max_age):
        with open(cache, "rb") as f:
            return f.read()
    req = urllib.request.Request(url, headers={"User-Agent": "sigillum/0.1"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
    with open(cache, "wb") as f:
        f.write(data)
    return data


def parse_tsl_certs(xml_bytes: bytes) -> list:
    root = ET.fromstring(xml_bytes)
    certs = []
    for el in root.iter():
        if not el.tag.endswith("X509Certificate"):
            continue
        txt = (el.text or "").strip()
        if not txt:
            continue
        try:
            der = base64.b64decode("".join(txt.split()))
            certs.append(x509.load_der_x509_certificate(der))
        except Exception:
            continue
    return certs


def verify_against_tsl(chain, tsl_certs):
    """Anchor chain in a TSL trust anchor.

    Returns (status, anchor_cert) where status ∈ {trusted, untrusted, error}.
    """
    if not chain:
        return "error", None
    top = chain[-1]

    if top.issuer == top.subject:
        top_der = top.public_bytes(serialization.Encoding.DER)
        for tc in tsl_certs:
            if tc.public_bytes(serialization.Encoding.DER) == top_der:
                return "trusted", tc
        return "untrusted", None

    for tc in tsl_certs:
        if tc.subject == top.issuer:
            if verify_cert_signed_by(top, tc):
                return "trusted", tc
    return "untrusted", None
