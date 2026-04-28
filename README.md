# sigillum

Verify and open Italian / eIDAS `.p7m` signed files (CAdES) from the command line.

`sigillum` parses a CMS SignedData blob, verifies the signature math, checks
all signed attributes, walks the certificate chain, and anchors it against the
EU Trust Service List (TSL) — printing a colour-coded report and a single
`VERDICT: VALID` / `INVALID` line. The embedded payload is then extracted to a
temp file and opened with the system viewer.

## Features

- Verifies the signer's RSA or ECDSA signature over the `signedAttrs` blob
- Checks the `messageDigest` and `contentType` signed attributes
- Reads the `signingTime` attribute and uses it for the validity-window check
- Walks the certificate chain inside the bundle and verifies every internal
  signature
- Anchors the chain in the eIDAS Trust Service List (Italian AGID TSL by
  default; override with `--tsl-url`); cached for a week under
  `~/.cache/sigillum/`
- Detects PDFs and refuses them politely (PAdES is a different format)
- Detects renamed `.p7m` files (e.g. `foo.pdf` whose bytes are still CMS) by
  sniffing the magic bytes
- Coloured TTY output, `NO_COLOR` honoured, plain when piped
- Returns exit code 0 only when **every** input file is `VALID` — useful in
  scripts

## Install

Requires Python 3.10+.

### From source (recommended for now)

```sh
pipx install -e ~/dev/sigillum
```

### Direct from GitHub

```sh
pipx install git+https://github.com/<your-user>/sigillum.git
```

For window-resize support on Linux desktops, also install `wmctrl`:

```sh
sudo apt install wmctrl
```

## Usage

```sh
sigillum file.p7m                          # verify and open
sigillum a.p7m b.p7m c.p7m                 # batch
sigillum file.p7m --no-open                # verify only, no viewer
sigillum file.p7m --no-tsl                 # skip EU TSL check (offline)
sigillum file.p7m --quiet-on-valid         # one-liner if VALID
sigillum file.p7m --tsl-url <URL>          # use a different TSL
```

### Sample output

```
── doc.pdf.p7m ─────────────────────────────
  Signer      MARIO ROSSI
  Issuer      InfoCamere Qualified Electronic Signature CA
  Signed      2026-04-22 09:31 UTC
  Cert life   2023-08-03 07:53 UTC → 2026-08-03 00:00 UTC

Cryptographic integrity
  ✓ Signature math         ok
  ✓ messageDigest attr     ok
  ✓ contentType attr       ok

Validity & trust
  ✓ Cert valid @ signing   ok
  ✓ Chain (1 cert)         ok
  ✓ EU TSL (eIDAS)         ok    anchor: InfoCamere Qualified Electronic Signature CA

VERDICT: VALID
```

## Limitations

- **CAdES only.** PAdES (signature embedded inside a PDF's `/ByteRange`) is
  not supported. Sniffed PDFs are rejected with a clear error.
- **Italian TSL by default.** Other member-state TSLs work via `--tsl-url`,
  but the LOTL (List of Lists) is not auto-walked yet.
- **No revocation checking.** CRL / OCSP are not consulted; a revoked but
  otherwise well-formed signature will still report VALID.
- **No timestamp-token validation.** If the signature carries an RFC 3161
  timestamp, it is not currently verified.

## License

MIT — see [LICENSE](LICENSE).
