# NetScope — Network Traffic Analysis & Anomaly Triage

**NetScope** is a defensive network-forensics prototype that turns a classic PCAP capture into bidirectional flow records, protocol statistics, top talkers and explainable anomaly findings. It includes a responsive investigation dashboard, a bounded PCAP parser, a deterministic synthetic capture, an API, tests and Docker deployment support.

> **Scope:** NetScope is an educational analysis tool. Its detection output is heuristic evidence for investigation, not a verdict that a host is compromised. It does not decrypt TLS, execute packet payloads, sniff live interfaces, or replace an enterprise NDR/SIEM platform.

## Product tour

- Upload a `.pcap`, `.cap` or `.dmp` capture (maximum 12 MiB by default).
- Parse classic PCAP with microsecond or nanosecond timestamps.
- Decode Ethernet (including up to two VLAN tags), RAW IP and Linux SLL v1 link layers.
- Inspect IPv4 / IPv6, TCP, UDP, ICMP, ARP and DNS question names.
- Aggregate conversations by bidirectional transport 5-tuple.
- Explore protocol distribution, top source talkers and a searchable flow table.
- Investigate findings with source, destination, evidence and MITRE ATT&CK context.
- Export the analysis as JSON.
- Load the bundled 94-packet synthetic capture without uploading a file.

## Detection catalogue

| Rule | Trigger (v1 defaults) | Interpretation |
|---|---|---|
| `NS-PORT-SCAN` | 10+ unique TCP destination ports from one source to one target | Vertical port scan pattern |
| `NS-SYN-BURST` | 20+ SYN-only packets to one destination service, where the source did not trip the port-scan rule | Concentrated connection burst; not proof of impact |
| `NS-DNS-ENTROPY` | DNS question length 55+ characters, or a 32+ character label with entropy at least 3.4 bits/character | Possible encoded DNS labels; false positives are expected |
| `NS-PERIODIC-BEACON` | 5+ connection events, mean interval 5–900 seconds, interval CV at most 0.15 | Regular periodicity; not proof of command and control |
| `NS-LARGE-TRANSFER` | 1,000,000+ bytes from a private source to a public destination | Large outbound volume; payload meaning is unknown |
| `NS-ICMP-SWEEP` | 10+ unique ICMP destinations from one source | Host-discovery pattern |
| `NS-ARP-CONFLICT` | 2+ MAC addresses claim the same ARP sender IPv4 address | Possible spoofing, proxy ARP or failover |

The rule thresholds are intentionally visible and straightforward to tune. Detection output includes caveats and evidence so an analyst can challenge the rule rather than treating a score as ground truth.

## Architecture

```text
Browser dashboard
      |
      v
FastAPI endpoints  ---- GET /api/healthz
      |
      +---- PCAP upload / synthetic capture
      |
      v
Bounded classic-PCAP parser
      |
      +---- Link-layer decode (Ethernet / RAW / SLL)
      +---- Network decode (IPv4 / IPv6 / ARP)
      +---- Transport decode (TCP / UDP / ICMP)
      +---- DNS question extraction
      |
      v
Flow aggregator + protocol counters
      |
      v
Explainable detection rules
      |
      v
JSON analysis state (in-memory) ---- dashboard / export
```

**Key engineering decisions**

1. **Offline parsing only.** No raw-socket privileges or packet capture daemon are required. This makes the project easier to run and safer to host.
2. **Bounded parsing.** The service limits upload bytes, record count and individual frame size; malformed/truncated records produce controlled errors.
3. **No payload execution.** Packet payloads are treated as bytes. Only a DNS question name is extracted for a specific heuristic.
4. **Bidirectional flows.** Both directions of the same transport endpoint pair are grouped under one flow ID while retaining first-seen direction counters.
5. **Volatile analysis state.** The original capture is not persisted by the application after request processing. The latest result is held in process memory and resets after a restart or free-instance spin-down.
6. **Explainable findings.** Every alert shows a rule ID, threshold evidence, confidence hint and a caveat.

## Quick start (Linux / WSL / macOS)

Python 3.10 or newer is required.

```bash
# 1. Extract the repository and enter it
cd netscope

# 2. Create an isolated environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install the app and developer tools
python -m pip install -e ".[dev]"

# 4. Start the dashboard
uvicorn netscope.main:app --reload --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000**. The synthetic analysis loads automatically. API documentation is at `/api/docs`; the health endpoint is `/healthz`.

### Run tests

```bash
pytest
```

### Run with Docker

```bash
docker compose up --build
```

Open **http://localhost:8000**. To change the local host port, run `PORT=8080 docker compose up --build`.

## Deploy to Render (free web service)

1. Create a public GitHub repository named `netscope-network-analyzer` and push this folder.
2. In Render, choose **New → Web Service** and connect the repository.
3. Choose **Docker** as the runtime, branch `main`, root directory blank, and the Free instance.
4. Do not add a custom `PORT` variable unless Render's service configuration requires one; the Docker image defaults to `10000` and honours Render's injected `PORT`.
5. Set Health Check Path to `/healthz` and deploy.
6. Verify `https://YOUR-SERVICE.onrender.com/healthz`, then open the root URL.

Render free instances sleep when idle. The application uses in-memory analysis state, so the currently loaded result resets on process restart or spin-down. PCAP uploads are capped at 12 MiB and 30,000 decoded packets by default; tune these limits for a different hosting plan.

## API reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/healthz` | Health and version |
| `POST` | `/api/demo` | Load bundled synthetic traffic and analyse it |
| `POST` | `/api/analyze` | Multipart upload field `file` with a classic PCAP |
| `GET` | `/api/analysis` | Retrieve the latest in-memory analysis |
| `GET` | `/api/rules` | Show the current rule catalogue |
| `GET` | `/api/export` | Download latest analysis JSON |
| `GET` | `/api/sample.pcap` | Download the synthetic capture |
| `GET` | `/api/docs` | Interactive OpenAPI documentation |

Example upload:

```bash
curl -F "file=@data/demo-traffic.pcap" http://127.0.0.1:8000/api/analyze
```

## Capture-format support and limitations

- Supports classic PCAP (not PCAPNG yet), version 2.2–2.4, Ethernet, RAW IP and Linux cooked capture v1.
- Supports IPv4 and IPv6 fixed headers plus common IPv6 extension headers; fragmented non-first IPv4 / IPv6 packets are skipped because their transport headers are not present in the fragment.
- Parses TCP, UDP, ICMP, ICMPv6, ARP and basic DNS query labels. DNS compression pointers are not followed.
- Does not reassemble IP fragments or TCP streams, parse TLS SNI, inspect HTTP content, decode encrypted traffic or reconstruct application sessions.
- Flow records are summaries, not full packet forensic records. Up to 500 largest flows and 100 initial packet records are included in the API response to bound browser work.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for more detail.

## Demo dataset

`data/demo-traffic.pcap` is synthetic. It contains benign background traffic plus deliberately constructed patterns for a vertical scan, SYN burst, long/high-entropy DNS labels, periodic connection events, a large outbound transfer, ARP ownership conflict and ICMP sweep. All IPs are lab/documentation examples, and the capture contains no user traffic.

Regenerate it with:

```bash
python scripts/generate_sample.py
cp data/demo-traffic.pcap src/netscope/data/demo-traffic.pcap
```

## Security notes

- Do not upload captures unless you have the right to analyse them. PCAP files can contain usernames, internal IP addresses, DNS history and other sensitive metadata.
- Upload contents are not retained in application-owned storage. Starlette multipart handling may use bounded temporary spooling for larger request bodies; reverse-proxy or platform request logs may still record request metadata.
- Public deployments can be abused for CPU consumption. Keep the upload and packet limits low, monitor usage and add authentication / rate limiting before offering unrestricted public uploads.
- The demo endpoint only analyses the bundled synthetic capture. It does not access host interfaces or the host filesystem.

## Roadmap

- PCAPNG and additional link-layer types.
- TCP stream reconstruction and DNS response correlation.
- Stateful alert suppression, allowlists and per-rule tuning.
- Persistent analysis history for a secured deployment.
- Optional Zeek JSON ingestion and enrichment.
- Background jobs for larger captures.

## License

MIT. See [`LICENSE`](LICENSE).
