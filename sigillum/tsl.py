"""eIDAS Trust Service List (TSL) anchor verification.

Anchors are extracted only from TSPService entries whose ServiceTypeIdentifier
is a CA service (CA/QC or CA/PKC) and whose ServiceStatus is "granted" at the
effective signing time. ServiceHistory is honored when eff_time is supplied so
that signatures made while a CA was active still validate after the CA is
later withdrawn — and signatures made before a CA was granted do not.
"""
from __future__ import annotations

import base64
import os
import time
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from sigillum.cms import verify_cert_signed_by

TSL_URL_IT = "https://eidas.agid.gov.it/TL/TSL-IT.xml"
TSL_CACHE_DIR = os.path.expanduser("~/.cache/sigillum")
TSL_CACHE = os.path.join(TSL_CACHE_DIR, "TSL-IT.xml")
TSL_MAX_AGE = 7 * 86400  # one week

_SVC_TYPE_PREFIX = "http://uri.etsi.org/TrstSvc/Svctype/"
_SVC_STATUS_PREFIX = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/"

ALLOWED_SERVICE_TYPES = frozenset({
    _SVC_TYPE_PREFIX + "CA/QC",
    _SVC_TYPE_PREFIX + "CA/PKC",
})

# Strict: only "granted" anchors a qualified signature. Pre-eIDAS statuses
# (undersupervision/accredited) are deliberately excluded; revisit if needed.
GRANTED_STATUSES = frozenset({
    _SVC_STATUS_PREFIX + "granted",
})


@dataclass(frozen=True)
class TSLAnchor:
    cert: x509.Certificate
    territory: str
    service_type: str


def fetch_tsl(url: str = TSL_URL_IT, cache: str = TSL_CACHE,
              max_age: int = TSL_MAX_AGE) -> bytes:
    os.makedirs(os.path.dirname(cache), exist_ok=True)
    if os.path.exists(cache) and (time.time() - os.path.getmtime(cache) < max_age):
        with open(cache, "rb") as f:
            return f.read()
    req = urllib.request.Request(url, headers={"User-Agent": "sigillum/0.2"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
    with open(cache, "wb") as f:
        f.write(data)
    return data


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _findall_local(parent, name: str):
    return [el for el in parent.iter() if _localname(el.tag) == name]


def _find_local(parent, name: str):
    for el in parent.iter():
        if _localname(el.tag) == name:
            return el
    return None


def _direct_child(parent, name: str):
    for el in list(parent):
        if _localname(el.tag) == name:
            return el
    return None


def _direct_children(parent, name: str):
    return [el for el in list(parent) if _localname(el.tag) == name]


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _certs_from_service_digital_id(sdi) -> list[x509.Certificate]:
    out = []
    for x509el in _findall_local(sdi, "X509Certificate"):
        txt = (x509el.text or "").strip()
        if not txt:
            continue
        try:
            der = base64.b64decode("".join(txt.split()))
            out.append(x509.load_der_x509_certificate(der))
        except Exception:
            continue
    return out


def _service_intervals(service_el):
    """Yield (svc_type, status, starting_time, sdi_el) for current + history."""
    info = _direct_child(service_el, "ServiceInformation")
    if info is not None:
        st = _direct_child(info, "ServiceTypeIdentifier")
        ss = _direct_child(info, "ServiceStatus")
        sst = _direct_child(info, "StatusStartingTime")
        sdi = _direct_child(info, "ServiceDigitalIdentity")
        yield (
            (st.text or "").strip() if st is not None else "",
            (ss.text or "").strip() if ss is not None else "",
            _parse_dt(sst.text) if sst is not None else None,
            sdi,
        )

    history = _direct_child(service_el, "ServiceHistory")
    if history is None:
        return
    for inst in _direct_children(history, "ServiceHistoryInstance"):
        st = _direct_child(inst, "ServiceTypeIdentifier")
        ss = _direct_child(inst, "ServiceStatus")
        sst = _direct_child(inst, "StatusStartingTime")
        sdi = _direct_child(inst, "ServiceDigitalIdentity")
        yield (
            (st.text or "").strip() if st is not None else "",
            (ss.text or "").strip() if ss is not None else "",
            _parse_dt(sst.text) if sst is not None else None,
            sdi,
        )


def _interval_active_at(start: datetime | None, eff_time: datetime | None) -> bool:
    """When eff_time is None, accept only entries with no constraint check.

    With eff_time given, the entry must have started at-or-before eff_time.
    Upper bound (when superseded) is enforced by preferring later-started
    entries; see parse_tsl_anchors.
    """
    if eff_time is None:
        return True
    if start is None:
        return True  # missing StatusStartingTime: don't reject on this alone
    return start <= eff_time


def parse_tsl_anchors(xml_bytes: bytes,
                      eff_time: datetime | None = None) -> list[TSLAnchor]:
    """Extract trust anchors from a TSL.

    Filters:
      - ServiceTypeIdentifier ∈ ALLOWED_SERVICE_TYPES
      - ServiceStatus ∈ GRANTED_STATUSES
      - When eff_time is given: status interval must cover eff_time. For each
        TSPService we pick the latest interval whose StatusStartingTime ≤
        eff_time and check that interval's status — so an anchor that was
        "granted" at signing time but later "withdrawn" is still trusted, and
        one not yet granted at signing time is rejected.
    """
    root = ET.fromstring(xml_bytes)
    territory_el = _find_local(root, "SchemeTerritory")
    territory = (territory_el.text or "").strip() if territory_el is not None else ""

    anchors: list[TSLAnchor] = []
    for svc in _findall_local(root, "TSPService"):
        intervals = list(_service_intervals(svc))
        if not intervals:
            continue

        if eff_time is None:
            chosen = intervals[0]  # current ServiceInformation
        else:
            candidates = [iv for iv in intervals if _interval_active_at(iv[2], eff_time)]
            if not candidates:
                continue
            # Latest start time wins (covers eff_time); None treated as -inf.
            chosen = max(
                candidates,
                key=lambda iv: iv[2] or datetime.min.replace(tzinfo=timezone.utc),
            )

        svc_type, status, _start, sdi = chosen
        if svc_type not in ALLOWED_SERVICE_TYPES:
            continue
        if status not in GRANTED_STATUSES:
            continue
        if sdi is None:
            continue
        for cert in _certs_from_service_digital_id(sdi):
            anchors.append(TSLAnchor(cert=cert, territory=territory,
                                     service_type=svc_type))
    return anchors


def parse_tsl_certs(xml_bytes: bytes) -> list[x509.Certificate]:
    """Back-compat shim: returns just certs from current granted CA services."""
    return [a.cert for a in parse_tsl_anchors(xml_bytes)]


def _normalize_anchors(anchors) -> list[TSLAnchor]:
    """Accept list[TSLAnchor] or list[Certificate] for back-compat."""
    out = []
    for a in anchors:
        if isinstance(a, TSLAnchor):
            out.append(a)
        else:
            out.append(TSLAnchor(cert=a, territory="", service_type=""))
    return out


def verify_against_tsl(chain, anchors):
    """Anchor chain in a TSL trust anchor.

    Returns (status, anchor) where:
      - status ∈ {trusted, untrusted, error}
      - anchor is a TSLAnchor (or None). For back-compat with the prior
        2-tuple API callers can still unpack 2 values; use anchor.cert /
        anchor.territory on the result.
    """
    if not chain:
        return "error", None
    norm = _normalize_anchors(anchors)
    top = chain[-1]

    if top.issuer == top.subject:
        top_der = top.public_bytes(serialization.Encoding.DER)
        for a in norm:
            if a.cert.public_bytes(serialization.Encoding.DER) == top_der:
                return "trusted", a
        return "untrusted", None

    for a in norm:
        if a.cert.subject == top.issuer:
            if verify_cert_signed_by(top, a.cert):
                return "trusted", a
    return "untrusted", None
