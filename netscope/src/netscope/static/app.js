(() => {
  const $ = (selector) => document.querySelector(selector);
  const state = { analysis: null, tab: "overview", flows: [], toastTimer: null };
  const root = $("#view-root");

  function esc(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  }
  function fmtBytes(value) {
    const bytes = Number(value) || 0;
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
    return `${bytes.toLocaleString()} B`;
  }
  function fmtTime(value) {
    if (!value) return "—";
    return new Date(Number(value) * 1000).toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }
  function notify(message, error = false) {
    const toast = $("#toast");
    toast.textContent = message;
    toast.classList.toggle("error", error);
    toast.classList.add("show");
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => toast.classList.remove("show"), 3500);
  }
  function setBusy(busy, message = "Analysing capture…") {
    $("#load-demo").disabled = busy;
    $("#upload-note").textContent = busy ? message.toUpperCase() : "SUPPORTED: CLASSIC PCAP · ETHERNET / RAW IP / LINUX SLL · MAX 12 MiB";
    if (busy) root.innerHTML = `<div class="loading-state"><div class="loader"></div><span>${esc(message)}</span></div>`;
  }
  async function request(url, options) {
    const response = await fetch(url, options);
    const contentType = response.headers.get("content-type") || "";
    const body = contentType.includes("application/json") ? await response.json() : await response.text();
    if (!response.ok) throw new Error((body && body.detail) || `Request failed (${response.status})`);
    return body;
  }
  function setAnalysis(analysis) {
    state.analysis = analysis;
    state.flows = analysis.flows || [];
    const meta = analysis.meta;
    $("#capture-name").textContent = meta.filename;
    $("#capture-meta").textContent = `${meta.packets.toLocaleString()} PACKETS · ${meta.flows.toLocaleString()} FLOWS · ${fmtBytes(meta.bytes)}`;
    $("#capture-status-title").textContent = "Capture analysed";
    $("#capture-status-sub").textContent = `${meta.packets.toLocaleString()} packets · ${analysis.alerts.length} detections`;
    $(".pulse-dot").classList.add("online");
    $("#side-alert-count").textContent = analysis.alerts.length;
    render();
  }
  async function loadDemo() {
    setBusy(true, "Loading synthetic capture and evaluating detection rules…");
    try {
      const result = await request("/api/demo", { method: "POST" });
      setAnalysis(result);
      notify("Synthetic investigation loaded. All rules evaluated.");
    } catch (error) {
      root.innerHTML = `<div class="empty-state">${esc(error.message)}</div>`;
      notify(error.message, true);
    } finally { setBusy(false); }
  }
  async function uploadFile(file) {
    if (!file) return;
    const data = new FormData();
    data.append("file", file);
    setBusy(true, `Uploading ${file.name} and analysing packets…`);
    try {
      const result = await request("/api/analyze", { method: "POST", body: data });
      setAnalysis(result);
      notify(`Capture analysed: ${result.meta.packets.toLocaleString()} packets.`);
    } catch (error) {
      root.innerHTML = `<div class="empty-state">${esc(error.message)}<br><br>Try the bundled demo capture or check the PCAP format.</div>`;
      notify(error.message, true);
    } finally {
      setBusy(false);
      $("#pcap-file").value = "";
    }
  }
  function render() {
    const analysis = state.analysis;
    if (!analysis) return;
    $("#breadcrumb-current").textContent = ({ overview: "Overview", flows: "Network flows", alerts: "Detection queue", rules: "Detection rules" })[state.tab];
    document.querySelectorAll("[data-tab]").forEach((item) => item.classList.toggle("active", item.dataset.tab === state.tab));
    if (state.tab === "overview") renderOverview(analysis);
    if (state.tab === "flows") renderFlows(analysis);
    if (state.tab === "alerts") renderAlerts(analysis);
    if (state.tab === "rules") renderRules(analysis);
  }
  function metric(label, value, foot, klass = "") {
    return `<div class="metric-card ${klass}"><div class="metric-label">${esc(label)}</div><div class="metric-value">${esc(value)}</div><div class="metric-foot">${esc(foot)}</div></div>`;
  }
  function renderOverview(analysis) {
    const m = analysis.meta;
    const high = analysis.alerts.filter((alert) => alert.severity === "high" || alert.severity === "critical").length;
    const critical = analysis.alerts.filter((alert) => alert.severity === "critical").length;
    const protocolMax = Math.max(1, ...analysis.protocols.map((row) => row.packets));
    const protocolRows = analysis.protocols.slice(0, 8).map((row) => `<div class="protocol-row"><span class="protocol-name">${esc(row.protocol)}</span><div class="bar-track"><div class="bar-fill" style="width:${Math.max(2, row.packets / protocolMax * 100)}%"></div></div><span class="protocol-count">${row.packets} pkts</span></div>`).join("");
    const talkers = analysis.top_talkers.slice(0, 6).map((row) => `<div class="talker-row"><span class="talker-ip">${esc(row.ip)}</span><span class="talker-bytes">${fmtBytes(row.bytes)}</span><span class="talker-packets">${row.packets} pkts</span></div>`).join("");
    const topAlerts = analysis.alerts.slice(0, 3).map(alertCard).join("");
    root.innerHTML = `
      <div class="metric-grid">
        ${metric("PACKETS OBSERVED", m.packets.toLocaleString(), `${m.sources} source addresses`)}
        ${metric("TOTAL TRAFFIC", fmtBytes(m.bytes), `${m.destinations} destination addresses`)}
        ${metric("BIDIRECTIONAL FLOWS", m.flows.toLocaleString(), `${m.duration_seconds.toFixed(1)} seconds captured`)}
        ${metric("DETECTIONS", analysis.alerts.length, "Explainable rule matches", "alert-metric")}
        ${metric("HIGH / CRITICAL", `${high} / ${critical}`, "Priority investigation", high ? "high-metric" : "")}
      </div>
      <div class="section-heading"><h2>Traffic profile</h2><span>PROTOCOL DISTRIBUTION / TOP TALKERS</span></div>
      <div class="overview-grid">
        <section class="panel"><div class="panel-head"><strong>Protocol mix</strong><span>PACKET COUNT</span></div><div class="panel-body">${protocolRows || '<div class="empty-state">No protocol data.</div>'}</div></section>
        <section class="panel"><div class="panel-head"><strong>Top source talkers</strong><span>BY OBSERVED BYTES</span></div><div class="panel-body">${talkers || '<div class="empty-state">No source data.</div>'}</div></section>
      </div>
      <div class="section-heading"><h2>Priority detections</h2><span>${analysis.alerts.length} TOTAL MATCHES</span></div>
      <div class="alert-grid">${topAlerts || '<div class="empty-state">No detection rules fired for this capture. This does not prove the network is safe.</div>'}</div>
      <div class="tab-row"><button class="tab-button" data-jump="flows">Explore all flows ↗</button><button class="tab-button" data-jump="alerts">Open detection queue ↗</button></div>`;
    root.querySelectorAll("[data-jump]").forEach((button) => button.addEventListener("click", () => switchTab(button.dataset.jump)));
  }
  function alertCard(alert) {
    const sev = alert.severity.toLowerCase();
    const evidence = (alert.evidence || []).map((line) => `<li>${esc(line)}</li>`).join("");
    return `<article class="alert-card sev-${esc(sev)}">
      <div class="alert-top"><span class="severity ${esc(sev)}">${esc(sev.toUpperCase())}</span><span class="alert-rule">${esc(alert.rule_id)} · ${esc(alert.id)}</span><span class="alert-confidence">CONFIDENCE ${esc(alert.confidence)}%</span></div>
      <h3>${esc(alert.title)}</h3><p>${esc(alert.summary)}</p>
      <div class="alert-route"><span>${esc(alert.source)}</span><b>→</b><span>${esc(alert.destination)}</span></div>
      <details><summary>Inspect evidence and context</summary><ul class="evidence-list">${evidence}</ul><div class="mitre">MITRE ATT&CK · ${esc(alert.mitre)}</div></details>
    </article>`;
  }
  function renderAlerts(analysis) {
    root.innerHTML = `<div class="section-heading"><h2>Detection queue</h2><span>${analysis.alerts.length} EXPLAINABLE RULE MATCHES</span></div>
      <div class="alert-grid">${analysis.alerts.map(alertCard).join("") || '<div class="empty-state">No detections in this capture. Absence of an alert is not proof of a clean network.</div>'}</div>
      <p class="table-note" style="margin-top:13px">Rules are heuristics for triage. Validate alerts against network context before drawing conclusions.</p>`;
  }
  function renderFlows(analysis) {
    root.innerHTML = `<div class="section-heading"><h2>Network flows</h2><span>${analysis.flows.length} FLOWS · BIDIRECTIONAL 5-TUPLE AGGREGATION</span></div>
      <div class="table-toolbar"><input class="table-search" id="flow-search" placeholder="Filter IP, port or protocol…" aria-label="Filter flows"><span class="table-note">SHOWING UP TO 500 LARGEST FLOWS</span></div>
      <div id="flow-table"></div>`;
    const search = $("#flow-search");
    const draw = () => {
      const query = search.value.trim().toLowerCase();
      const rows = analysis.flows.filter((flow) => [flow.src, flow.dst, flow.src_port, flow.dst_port, flow.transport, flow.app_protocol, flow.flow_id].join(" ").toLowerCase().includes(query));
      $("#flow-table").innerHTML = `<div class="table-wrap"><table class="data-table"><thead><tr><th>FLOW ID</th><th>SOURCE</th><th>DESTINATION</th><th>PROTOCOL</th><th>PACKETS</th><th>BYTES</th><th>DURATION</th><th>SYN / ACK</th></tr></thead><tbody>${rows.slice(0, 500).map((flow) => `<tr><td>${esc(flow.flow_id)}</td><td>${esc(flow.src)}${flow.src_port ? `:${flow.src_port}` : ""}</td><td>${esc(flow.dst)}${flow.dst_port ? `:${flow.dst_port}` : ""}</td><td><span class="proto-pill">${esc(flow.app_protocol)}</span></td><td>${flow.packets}</td><td>${fmtBytes(flow.bytes)}</td><td>${flow.duration_seconds.toFixed(2)}s</td><td>${flow.syn} / ${flow.ack}</td></tr>`).join("") || `<tr><td colspan="8">No flows match that filter.</td></tr>`}</tbody></table></div>`;
    };
    search.addEventListener("input", draw);
    draw();
  }
  function renderRules(analysis) {
    root.innerHTML = `<div class="section-heading"><h2>Detection rules</h2><span>TRANSPARENT HEURISTICS / V1.0</span></div>
      <div class="rules-grid">${analysis.rules.map((rule) => `<article class="rule-card"><div class="rule-id">${esc(rule.id)}</div><strong>${esc(rule.name)}</strong><p>TRIGGER: ${esc(rule.threshold)}</p><span class="table-note">CONFIDENCE CLASS: ${esc(rule.confidence)}</span></article>`).join("")}</div>
      <div class="panel" style="margin-top:14px"><div class="panel-head"><strong>Interpretation notes</strong><span>READ BEFORE TRIAGE</span></div><div class="panel-body"><ul class="evidence-list"><li>Port scans and SYN bursts are based on packets present in the capture; dropped traffic can change counts.</li><li>Long DNS labels and periodic connections are heuristics, not proof of command-and-control or tunnelling.</li><li>Large outbound volume does not reveal encrypted payload contents or establish data theft.</li><li>ARP conflicts can be caused by legitimate proxy ARP, virtual IP failover or capture artefacts.</li><li>NetScope is an educational defensive analysis prototype, not a replacement for a full NDR platform.</li></ul></div></div>`;
  }
  function switchTab(tab) {
    if (!["overview", "flows", "alerts", "rules"].includes(tab)) return;
    state.tab = tab;
    render();
  }

  document.querySelectorAll("[data-tab]").forEach((item) => item.addEventListener("click", (event) => {
    event.preventDefault();
    switchTab(item.dataset.tab);
    history.replaceState(null, "", `#${item.dataset.tab}`);
  }));
  $("#load-demo").addEventListener("click", loadDemo);
  $("#pcap-file").addEventListener("change", (event) => uploadFile(event.target.files[0]));
  $("#drop-zone").addEventListener("click", () => $("#pcap-file").click());
  $("#drop-zone").addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); $("#pcap-file").click(); } });
  ["dragenter", "dragover"].forEach((name) => $("#drop-zone").addEventListener(name, (event) => { event.preventDefault(); $("#drop-zone").classList.add("dragover"); }));
  ["dragleave", "drop"].forEach((name) => $("#drop-zone").addEventListener(name, (event) => { event.preventDefault(); $("#drop-zone").classList.remove("dragover"); }));
  $("#drop-zone").addEventListener("drop", (event) => uploadFile(event.dataTransfer.files[0]));
  $("#export-json").addEventListener("click", async () => {
    try {
      const response = await fetch("/api/export");
      if (!response.ok) throw new Error("Analyse a capture before exporting.");
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url; anchor.download = "netscope-analysis.json"; anchor.click();
      URL.revokeObjectURL(url);
    } catch (error) { notify(error.message, true); }
  });

  loadDemo();
})();
