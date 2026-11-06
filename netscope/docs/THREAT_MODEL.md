# NetScope threat model

## Assets

- Uploaded packet captures and derived metadata.
- Endpoint addresses, DNS questions, ports and timing information.
- Analysis state and export JSON.
- Service availability and CPU / memory resources.

## Trust boundaries

1. Browser to HTTP API.
2. User-supplied PCAP bytes to parser.
3. Parsed data to detection and rendering logic.
4. Public demo instance to shared process memory.

## Risks and current mitigations

| Risk | Mitigation in this prototype | Remaining work |
|---|---|---|
| Oversized upload / resource exhaustion | 12 MiB upload limit, 30,000 packet limit, 1 MiB frame limit | Add per-IP / per-account rate limits and job timeouts at the edge |
| Malformed PCAP causing parser failure | Bounds checks, version / link-type allowlist, controlled parse errors | Fuzzing and property-based tests |
| Stored-file malware or payload execution | Upload is parsed as untrusted bytes; payloads are never executed or persisted by the application | Isolate workers for large or untrusted captures |
| HTML / script injection via crafted DNS names or addresses | Dashboard escapes PCAP-derived strings before HTML rendering | Add CSP headers and a dedicated security review |
| Sensitive metadata disclosure | No application-owned original-capture persistence; no file listing endpoint | Add authentication, tenant isolation and configurable retention before production use |
| Alert misinterpretation | Explainable evidence, visible thresholds and caveats | Calibrate against labelled data and add analyst feedback |
| Volatile / shared process state | Prototype explicitly documents single-process in-memory state | Use job IDs and tenant-scoped durable storage for multi-worker deployments |

## Out of scope

NetScope does not perform active scanning, packet injection, credential interception, TLS decryption, endpoint monitoring or automatic containment. It is a passive offline PCAP analysis prototype.

## Safe operating guidance

- Analyse only captures you are authorised to inspect.
- Keep sample captures synthetic when demonstrating publicly.
- Do not publish production PCAPs, DNS histories, internal IP inventories or exported analysis containing customer data.
- Treat all detections as leads requiring validation.
