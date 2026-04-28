"""sigillum CLI: verify and open .p7m signed files."""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
import warnings
from datetime import datetime, timezone

# Italian TSL contains certs with attributes longer than RFC 5280's 64-char
# limit; cryptography's RFC4514 serializer warns about this. Harmless here.
warnings.filterwarnings("ignore", message=r"Attribute's length must by .*")

from cryptography import x509

from sigillum.cms import (
    build_chain,
    cert_validity,
    check_content_type,
    check_eku,
    check_message_digest,
    find_signer_cert,
    get_payload,
    get_signing_time,
    is_pdf,
    load_p7m,
    looks_like_cms,
    verify_chain_signatures,
    verify_sig,
)
from sigillum.output import bold, cn_of, dim, green, red, status_line, yellow
from sigillum.tsl import TSL_URL_IT, fetch_tsl, parse_tsl_certs, verify_against_tsl
from sigillum.viewer import open_file_large


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="sigillum",
        description="Verify and open eIDAS/CAdES .p7m signed files.",
    )
    p.add_argument("files", nargs="+", help="One or more .p7m files")
    p.add_argument("--no-tsl", action="store_true",
                   help="Skip EU trust list (eIDAS TSL) check")
    p.add_argument("--tsl-url", default=TSL_URL_IT,
                   help="TSL XML URL (default: Italian AGID TSL)")
    p.add_argument("--no-open", action="store_true",
                   help="Do not launch a viewer for the extracted payload")
    p.add_argument("--quiet-on-valid", action="store_true",
                   help="Suppress detailed output if VERDICT is VALID")
    return p.parse_args(argv)


def verify_file(path: str, args) -> bool:
    """Process one file. Returns True if VALID."""
    src_name = os.path.basename(path)
    with open(path, "rb") as f:
        data = f.read()

    if is_pdf(data):
        print(red(f"{src_name}: input is a PDF, not a CMS .p7m wrapper. "
                  "PAdES (sig embedded inside PDF) is not supported."))
        return False

    if not looks_like_cms(data):
        print(yellow(f"{src_name}: bytes do not look like CMS (DER/base64); parse may fail"))

    try:
        ci = load_p7m(data)
    except Exception as e:
        print(red(f"{src_name}: not a valid CMS file: {e}"))
        return False
    if ci["content_type"].native != "signed_data":
        print(red(f"{src_name}: not signed_data ({ci['content_type'].native})"))
        return False

    sd = ci["content"]
    try:
        payload = get_payload(sd)
    except ValueError as e:
        print(red(f"{src_name}: {e}"))
        return False

    signer_info = sd["signer_infos"][0]
    signer_asn1, all_asn1 = find_signer_cert(sd, signer_info)
    cert = x509.load_der_x509_certificate(signer_asn1.dump())

    sig_ok = verify_sig(cert, signer_info, payload)
    md_ok = check_message_digest(signer_info, payload)
    ct_ok = check_content_type(signer_info, sd)

    nb, na = cert_validity(cert)
    now = datetime.now(timezone.utc)
    in_window_now = nb <= now <= na

    signing_time = get_signing_time(signer_info)
    in_window_signed = nb <= signing_time <= na if signing_time else None

    eku_notes = check_eku(cert)
    chain = build_chain(signer_asn1.dump(), [c.dump() for c in all_asn1])
    chain_ok, chain_err = verify_chain_signatures(chain)

    tsl_status = "skipped"
    tsl_anchor = None
    if not args.no_tsl:
        try:
            tsl_xml = fetch_tsl(url=args.tsl_url)
            tsl_certs = parse_tsl_certs(tsl_xml)
            tsl_status, tsl_anchor = verify_against_tsl(chain, tsl_certs)
        except Exception as e:
            tsl_status = f"error: {e}"

    window_ok = in_window_signed if signing_time is not None else in_window_now
    tsl_ok = True if args.no_tsl else (tsl_status == "trusted")
    all_ok = (sig_ok and window_ok and chain_ok
              and (md_ok is not False) and (ct_ok is not False) and tsl_ok)

    if all_ok and args.quiet_on_valid:
        print(f"{src_name}: {bold(green('VALID'))}")
    else:
        _render(src_name, cert, signing_time, nb, na,
                sig_ok, md_ok, ct_ok, in_window_signed, in_window_now,
                chain, chain_ok, chain_err, tsl_status, tsl_anchor,
                eku_notes, args.no_tsl, all_ok)

    if not all_ok:
        ans = input("Open anyway? [y/N] ").strip().lower()
        if ans != "y":
            return False

    if not args.no_open:
        inner = src_name[:-4] if src_name.lower().endswith(".p7m") else src_name + ".out"
        suffix = os.path.splitext(inner)[1] or ".bin"
        fd, tmp = tempfile.mkstemp(prefix="sigillum_", suffix=suffix)
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
        print(dim(f"payload → {tmp}"))
        open_file_large(tmp)

    return all_ok


def _render(src_name, cert, signing_time, nb, na,
            sig_ok, md_ok, ct_ok, in_window_signed, in_window_now,
            chain, chain_ok, chain_err, tsl_status, tsl_anchor,
            eku_notes, no_tsl, all_ok):
    fmt = "%Y-%m-%d %H:%M %Z"
    print()
    print(bold(f"── {src_name} ─────────────────────────────"))
    print(f"  {bold('Signer'):<10}  {bold(cn_of(cert.subject))}")
    print(f"  {'Issuer':<10}  {cn_of(cert.issuer)}")
    if signing_time is not None:
        print(f"  {'Signed':<10}  {signing_time.strftime(fmt)}")
    else:
        print(f"  {'Signed':<10}  {yellow('<no signingTime attribute>')}")
    print(f"  {'Cert life':<10}  {nb.strftime(fmt)} → {na.strftime(fmt)}")
    print()
    print(bold("Cryptographic integrity"))
    print(status_line("Signature math",     sig_ok))
    print(status_line("messageDigest attr", md_ok))
    print(status_line("contentType attr",   ct_ok))
    print()
    print(bold("Validity & trust"))
    if signing_time is not None:
        print(status_line("Cert valid @ signing", in_window_signed))
    else:
        print(status_line("Cert valid now",       in_window_now,
                          "no signing time → using current clock"))
    n = len(chain)
    print(status_line(f"Chain ({n} cert{'s' if n != 1 else ''})",
                      chain_ok, chain_err or ""))

    if no_tsl:
        print(status_line("EU TSL (eIDAS)", None, "skipped (--no-tsl)"))
    elif tsl_status == "trusted":
        anchor = cn_of(tsl_anchor.subject) if tsl_anchor else "?"
        print(status_line("EU TSL (eIDAS)", True, f"anchor: {anchor}"))
    elif tsl_status == "untrusted":
        print(status_line("EU TSL (eIDAS)", False, "no matching anchor"))
    else:
        print(status_line("EU TSL (eIDAS)", False, tsl_status))

    if eku_notes:
        print(f"  {yellow('!')} KeyUsage/EKU         {dim('; '.join(eku_notes))}")

    print()
    if all_ok:
        print(bold(green("VERDICT: VALID")))
    else:
        print(bold(red("VERDICT: INVALID / INCOMPLETE")))
    print()


def main(argv=None) -> int:
    args = parse_args(argv)
    all_valid = True
    for path in args.files:
        if not os.path.exists(path):
            print(red(f"not found: {path}"))
            all_valid = False
            continue
        ok = verify_file(path, args)
        all_valid = all_valid and ok
    sys.exit(0 if all_valid else 1)


if __name__ == "__main__":
    main()
