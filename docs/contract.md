# Runtime contract

## Verdicts and exit codes

| Verdict | Meaning | CLI exit | Proxy action |
|---|---|---:|---|
| clean | Scan completed and found no protected material | 0 | Forward |
| block | Scan completed and found protected material | 10 | HTTP 403 |
| error | Scanner/config/runtime could not establish a verdict | 20 | HTTP 503 |
| disabled | An administrator explicitly disabled scanning | 20 | HTTP 503 |

Unknown schemas, verdicts, targets, and fields are errors. Callers must never
interpret absence, timeout, or malformed output as clean.

## Startup

serve runs a benign fixture and the baseline scannerctl-canary must-detect
fixture against the exact backend/config before binding its socket. It refuses
to start unless the first is clean and the second is block.

## Routing

Route files use schemas/routes-v1.schema.json. Incoming Host selects an exact
route. Credentials are read from the declared environment variable only after
the request is clean and are never logged. Unknown hosts deny with HTTP 421.

## Request representation

The proxy scans the request body exactly as received and forwards exactly
those bytes. It therefore refuses, with HTTP 415 and before any scan, a request
whose Content-Encoding is anything other than identity (each listed coding and
each repeated header is checked) and any request carrying Transfer-Encoding,
whose framing would differ from the Content-Length bytes it inspected. Encoded
bodies are never decompressed, so a compressed must-detect payload or a
decompression bomb cannot reach the scanner or the upstream. Denials are
counted in scannerctl_request_denied_total by reason.

## Runtime network boundary

scan and self-test make no network requests. serve makes network requests only
to the statically configured upstream after a clean verdict. Backend binaries,
rules, config, and updates are supplied at build/provision time.

## Metrics

The Prometheus endpoint exposes one counter for each verdict, one counter for
each pre-scan denial reason, cumulative scan
duration/bytes, last-scan timestamp, startup canary state/timestamp, and
runtime/config identity. scannerctl_last_scan_timestamp_seconds = 0 is the
explicit no-data state and must not be rendered green by consumers.
