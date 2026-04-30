"""Tests for TSL service filter (type / status / history)."""
from __future__ import annotations

import base64
import datetime as _dt

from cryptography.hazmat.primitives import serialization

from sigillum.tsl import parse_tsl_anchors


def _b64_cert(cert) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def _service(svc_type: str, status: str, starting_time: str, b64_cert: str,
             history: str = "") -> str:
    return f"""
      <TSPService>
        <ServiceInformation>
          <ServiceTypeIdentifier>{svc_type}</ServiceTypeIdentifier>
          <ServiceName><Name xml:lang="en">test</Name></ServiceName>
          <ServiceDigitalIdentity>
            <DigitalId>
              <X509Certificate>{b64_cert}</X509Certificate>
            </DigitalId>
          </ServiceDigitalIdentity>
          <ServiceStatus>{status}</ServiceStatus>
          <StatusStartingTime>{starting_time}</StatusStartingTime>
        </ServiceInformation>
        {history}
      </TSPService>
    """


def _tsl(territory: str, services: str) -> bytes:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <SchemeTerritory>{territory}</SchemeTerritory>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation><TSPName><Name xml:lang="en">TSP</Name></TSPName></TSPInformation>
      <TSPServices>
        {services}
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>
""".encode()


CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"
CA_PKC = "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC"
TSA = "http://uri.etsi.org/TrstSvc/Svctype/TSA"
GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
WITHDRAWN = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"
UNDERSUP = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision"


def test_only_granted_ca_qc_anchors_returned(self_signed):
    _key, cert = self_signed
    b64 = _b64_cert(cert)
    services = "".join([
        _service(CA_QC, GRANTED, "2020-01-01T00:00:00Z", b64),
        _service(CA_QC, WITHDRAWN, "2020-01-01T00:00:00Z", b64),
        _service(TSA, GRANTED, "2020-01-01T00:00:00Z", b64),
        _service(CA_QC, UNDERSUP, "2020-01-01T00:00:00Z", b64),  # pre-eIDAS, excluded
    ])
    anchors = parse_tsl_anchors(_tsl("IT", services))
    assert len(anchors) == 1
    assert anchors[0].service_type == CA_QC
    assert anchors[0].territory == "IT"


def test_ca_pkc_accepted(self_signed):
    _key, cert = self_signed
    services = _service(CA_PKC, GRANTED, "2020-01-01T00:00:00Z", _b64_cert(cert))
    anchors = parse_tsl_anchors(_tsl("DE", services))
    assert len(anchors) == 1
    assert anchors[0].service_type == CA_PKC
    assert anchors[0].territory == "DE"


def test_no_anchor_when_all_withdrawn(self_signed):
    _key, cert = self_signed
    services = _service(CA_QC, WITHDRAWN, "2020-01-01T00:00:00Z", _b64_cert(cert))
    assert parse_tsl_anchors(_tsl("IT", services)) == []


def test_service_history_grants_past_anchor(self_signed):
    """Currently withdrawn but granted at signing time → still trusted then."""
    _key, cert = self_signed
    b64 = _b64_cert(cert)
    history = f"""
        <ServiceHistory>
          <ServiceHistoryInstance>
            <ServiceTypeIdentifier>{CA_QC}</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">test</Name></ServiceName>
            <ServiceDigitalIdentity>
              <DigitalId><X509Certificate>{b64}</X509Certificate></DigitalId>
            </ServiceDigitalIdentity>
            <ServiceStatus>{GRANTED}</ServiceStatus>
            <StatusStartingTime>2018-01-01T00:00:00Z</StatusStartingTime>
          </ServiceHistoryInstance>
        </ServiceHistory>
    """
    services = _service(CA_QC, WITHDRAWN, "2024-01-01T00:00:00Z", b64,
                        history=history)

    eff_at_grant = _dt.datetime(2020, 6, 1, tzinfo=_dt.timezone.utc)
    anchors_then = parse_tsl_anchors(_tsl("IT", services), eff_time=eff_at_grant)
    assert len(anchors_then) == 1

    eff_after_withdraw = _dt.datetime(2025, 6, 1, tzinfo=_dt.timezone.utc)
    anchors_now = parse_tsl_anchors(_tsl("IT", services),
                                    eff_time=eff_after_withdraw)
    assert anchors_now == []


def test_eff_time_before_grant_rejects(self_signed):
    """Signature predating CA's grant must not be anchored."""
    _key, cert = self_signed
    services = _service(CA_QC, GRANTED, "2022-01-01T00:00:00Z", _b64_cert(cert))
    eff = _dt.datetime(2020, 1, 1, tzinfo=_dt.timezone.utc)
    assert parse_tsl_anchors(_tsl("IT", services), eff_time=eff) == []
