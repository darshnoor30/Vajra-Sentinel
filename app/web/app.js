"use strict";

const state = { detections: [], selected: null, severity: "", about: null };
const byId = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value ?? "—")
  .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;").replaceAll("'", "&#039;");

async function api(path, options = {}) {
  const response = await fetch(path, { ...options, headers: { "Content-Type": "application/json", ...(options.headers || {}) } });
  let payload = null;
  try { payload = await response.json(); } catch { payload = {}; }
  if (!response.ok) throw new Error(payload.detail || `Request failed (${response.status})`);
  return payload;
}

function toast(message, error = false) {
  const element = byId("toast");
  element.textContent = message;
  element.className = error ? "show error" : "show";
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => { element.className = ""; }, 3300);
}

function setClock() {
  byId("clock").textContent = `${new Date().toISOString().slice(11, 19)} UTC`;
}

function setScore(score) {
  byId("health-score").textContent = score;
  byId("score-bar").style.width = `${score}%`;
  const label = score >= 85 ? "Healthy" : score >= 65 ? "Guarded" : score >= 40 ? "Elevated" : "Critical";
  byId("posture-copy").textContent = `${label} posture · transparent severity-weighted score`;
}

function renderSeverities(severity) {
  const order = ["critical", "high", "medium", "low", "info"];
  const maximum = Math.max(...Object.values(severity), 1);
  byId("severity-bars").innerHTML = order.map((name) => {
    const count = severity[name] || 0;
    const width = Math.max(2, Math.round((count / maximum) * 100));
    return `<div class="severity-row"><label>${name}</label><div class="bar"><span class="bar-${name}" data-width="${width}"></span></div><strong>${count}</strong></div>`;
  }).join("");
  document.querySelectorAll("[data-width]").forEach((bar) => { bar.style.width = `${bar.dataset.width}%`; });
}

function renderTrend(trend) {
  const svg = byId("trend-chart");
  svg.replaceChildren();
  const ns = "http://www.w3.org/2000/svg";
  const defs = document.createElementNS(ns, "defs");
  const gradient = document.createElementNS(ns, "linearGradient");
  gradient.id = "areaGradient"; gradient.setAttribute("x1", "0"); gradient.setAttribute("y1", "0"); gradient.setAttribute("x2", "0"); gradient.setAttribute("y2", "1");
  [["0%", "#2de0c1", ".24"], ["100%", "#2de0c1", "0"]].forEach(([offset, color, opacity]) => {
    const stop = document.createElementNS(ns, "stop"); stop.setAttribute("offset", offset); stop.setAttribute("stop-color", color); stop.setAttribute("stop-opacity", opacity); gradient.append(stop);
  });
  defs.append(gradient); svg.append(defs);
  for (let y = 30; y <= 190; y += 40) {
    const line = document.createElementNS(ns, "line"); line.setAttribute("x1", "35"); line.setAttribute("x2", "740"); line.setAttribute("y1", y); line.setAttribute("y2", y); line.setAttribute("class", "grid-line"); svg.append(line);
  }
  if (!trend.length) {
    const text = document.createElementNS(ns, "text"); text.setAttribute("x", "380"); text.setAttribute("y", "112"); text.setAttribute("text-anchor", "middle"); text.setAttribute("class", "empty-chart"); text.textContent = "No detection timeline yet"; svg.append(text); return;
  }
  const max = Math.max(...trend.map((item) => item.count), 1);
  const step = trend.length === 1 ? 0 : 680 / (trend.length - 1);
  const points = trend.map((item, index) => [45 + index * step, 190 - (item.count / max) * 145]);
  const area = document.createElementNS(ns, "path");
  area.setAttribute("d", `M ${points[0][0]} 190 L ${points.map((p) => `${p[0]} ${p[1]}`).join(" L ")} L ${points.at(-1)[0]} 190 Z`); area.setAttribute("class", "trend-area"); svg.append(area);
  const line = document.createElementNS(ns, "polyline"); line.setAttribute("points", points.map((p) => p.join(",")).join(" ")); line.setAttribute("class", "trend-line"); svg.append(line);
  points.forEach((point, index) => {
    const dot = document.createElementNS(ns, "circle"); dot.setAttribute("cx", point[0]); dot.setAttribute("cy", point[1]); dot.setAttribute("r", "4"); dot.setAttribute("class", "trend-dot"); svg.append(dot);
    const label = document.createElementNS(ns, "text"); label.setAttribute("x", point[0]); label.setAttribute("y", "211"); label.setAttribute("text-anchor", "middle"); label.setAttribute("class", "chart-label"); label.textContent = trend[index].bucket.slice(11) || trend[index].bucket; svg.append(label);
  });
}

function renderDetections(items) {
  state.detections = items;
  const body = byId("detections-body");
  if (!items.length) { body.innerHTML = '<tr><td colspan="6" class="empty">No findings match this filter.</td></tr>'; return; }
  body.innerHTML = items.map((item) => `
    <tr>
      <td class="detection-name"><strong>${escapeHtml(item.title)}</strong><span><span class="severity ${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span> · ${escapeHtml(item.rule_id)}</span></td>
      <td><span class="source-tag">${escapeHtml(item.source)}</span></td>
      <td>${escapeHtml(item.src_ip)} → ${escapeHtml(item.dest_ip)}</td>
      <td>${escapeHtml(item.confidence)}%</td>
      <td><span class="status-tag ${escapeHtml(item.status)}">${escapeHtml(item.status)}</span></td>
      <td><button class="inspect" data-detection-id="${item.id}" type="button">Inspect →</button></td>
    </tr>`).join("");
}

function renderIncidents(items) {
  byId("incident-list").innerHTML = items.length ? items.map((item) => `
    <div class="list-item">
      <div><strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.summary)}</p></div>
      <div class="list-meta"><span class="severity ${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span><span>${item.detection_count} signal${item.detection_count === 1 ? "" : "s"}</span><span class="status-tag ${escapeHtml(item.status)}">${escapeHtml(item.status)}</span></div>
    </div>`).join("") : '<div class="empty">No open incidents.</div>';
}

function renderBlocks(items) {
  byId("block-list").innerHTML = items.length ? items.map((item) => `
    <div class="list-item">
      <div><strong>${escapeHtml(item.ip)}</strong><p>${escapeHtml(item.reason)}</p></div>
      <div class="list-meta"><span>${escapeHtml(item.mode)}</span><span class="status-tag contained">${escapeHtml(item.status)}</span></div>
    </div>`).join("") : '<div class="empty">No containment actions recorded.</div>';
}

function renderModel(model) {
  const ready = model.status === "ready";
  byId("model-dot").classList.toggle("ready", ready);
  byId("model-status").textContent = ready ? "Model ready" : "Rules-only mode";
  byId("model-origin").textContent = model.data_origin || "not loaded";
  byId("model-threshold").textContent = model.threshold ? Number(model.threshold).toFixed(2) : "—";
  byId("model-prauc").textContent = model.metrics?.pr_auc != null ? Number(model.metrics.pr_auc).toFixed(3) : "—";
  byId("model-fpr").textContent = model.metrics?.false_positive_rate != null ? `${(Number(model.metrics.false_positive_rate) * 100).toFixed(2)}%` : "—";
  byId("model-warning").textContent = model.data_origin === "synthetic-smoke-test"
    ? "SMOKE-TEST MODEL · validates the pipeline only; these metrics are not a real-world performance claim."
    : ready ? "Production candidate · validate against current local traffic before enabling any response policy." : (model.reason || "Train and verify a model to enable flow scoring.");
}

async function refresh() {
  try {
    const [health, metrics, detections, incidents, blocks, model, about] = await Promise.all([
      api("/api/v1/health"), api("/api/v1/metrics"), api(`/api/v1/detections?limit=50${state.severity ? `&severity=${state.severity}` : ""}`),
      api("/api/v1/incidents?limit=12"), api("/api/v1/response/blocks?limit=10"), api("/api/v1/model"), api("/api/v1/about")
    ]);
    state.about = about;
    byId("system-status").textContent = health.status.toUpperCase();
    document.querySelector(".pulse").classList.add("ready");
    byId("mode-badge").textContent = `${about.ips_mode.toUpperCase()} IPS`;
    byId("response-mode").textContent = about.ips_mode.toUpperCase();
    byId("containment-copy").textContent = `Reversible actions in ${about.ips_mode} mode`;
    byId("data-label").textContent = about.demo_mode ? "VERIFIED LAB DATA · CLEARLY LABELED" : "LIVE SENSOR DATA";
    setScore(metrics.health_score);
    byId("event-count").textContent = metrics.events.toLocaleString();
    byId("priority-count").textContent = (metrics.severity.critical + metrics.severity.high).toLocaleString();
    byId("incident-count").textContent = metrics.open_incidents.toLocaleString();
    byId("block-count").textContent = metrics.active_blocks.toLocaleString();
    renderSeverities(metrics.severity); renderTrend(metrics.trend); renderDetections(detections.items);
    renderIncidents(incidents.items); renderBlocks(blocks.items); renderModel(model);
    byId("source-summary").textContent = Object.entries(metrics.sources).map(([key, value]) => `${key} ${value}`).join(" · ") || "No signals";
  } catch (error) {
    byId("system-status").textContent = "DEGRADED"; toast(error.message, true);
  }
}

function openDetection(id) {
  const item = state.detections.find((candidate) => candidate.id === id);
  if (!item) return;
  state.selected = item;
  byId("dialog-title").textContent = item.title;
  const techniques = item.mitre_techniques.length ? item.mitre_techniques.join(", ") : "No automatic mapping";
  byId("dialog-content").innerHTML = `
    <div class="evidence-grid">
      <div><span>Severity / confidence</span><strong>${escapeHtml(item.severity)} · ${item.confidence}%</strong></div>
      <div><span>Rule / source</span><strong>${escapeHtml(item.rule_id)} · ${escapeHtml(item.source)}</strong></div>
      <div><span>Network path</span><strong>${escapeHtml(item.src_ip)} → ${escapeHtml(item.dest_ip)}</strong></div>
      <div><span>MITRE ATT&amp;CK</span><strong>${escapeHtml(techniques)}</strong></div>
    </div>
    <div class="evidence-block"><span>What was observed</span><p>${escapeHtml(item.description)}</p></div>
    <div class="evidence-block"><span>Recommended analyst action</span><p>${escapeHtml(item.recommended_action)}</p></div>
    <div class="evidence-block"><span>Structured evidence</span><pre>${escapeHtml(JSON.stringify(item.evidence, null, 2))}</pre></div>`;
  byId("contain-button").hidden = !item.response_eligible || item.status === "contained";
  byId("contain-button").textContent = state.about?.ips_mode === "active" ? "Contain source" : "Simulate containment";
  byId("evidence-dialog").showModal();
}

async function containSelected() {
  if (!state.selected) return;
  const key = window.prompt("Enter the local API key to authorize this audited action:");
  if (!key) return;
  try {
    const result = await api(`/api/v1/detections/${state.selected.id}/contain`, { method: "POST", headers: { "X-API-Key": key }, body: JSON.stringify({ ttl_seconds: 900, reason: "Analyst-approved dashboard containment" }) });
    toast(`${result.status === "simulated" ? "Simulated" : "Active"} TTL block recorded for ${result.ip}`);
    byId("evidence-dialog").close(); await refresh();
  } catch (error) { toast(error.message, true); }
}

document.addEventListener("DOMContentLoaded", () => {
  setClock(); window.setInterval(setClock, 1000); refresh(); window.setInterval(refresh, 30000);
  byId("refresh").addEventListener("click", refresh);
  byId("run-demo").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    const original = button.innerHTML;
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    button.innerHTML = '<span aria-hidden="true">⟳</span> Replaying lab…';
    try { const result = await api("/api/v1/demo/scenarios/multi-stage", { method: "POST" }); await refresh(); toast(`Clean replay complete · ${result.events_ingested} events · ${result.detections_created} findings`); }
    catch (error) { toast(error.message, true); }
    finally { button.disabled = false; button.removeAttribute("aria-busy"); button.innerHTML = original; }
  });
  document.querySelector(".filters").addEventListener("click", async (event) => {
    const button = event.target.closest("[data-severity]"); if (!button) return;
    document.querySelectorAll(".filter").forEach((item) => item.classList.remove("active")); button.classList.add("active"); state.severity = button.dataset.severity; await refresh();
  });
  byId("detections-body").addEventListener("click", (event) => { const button = event.target.closest("[data-detection-id]"); if (button) openDetection(Number(button.dataset.detectionId)); });
  byId("close-dialog").addEventListener("click", () => byId("evidence-dialog").close());
  byId("dismiss-dialog").addEventListener("click", () => byId("evidence-dialog").close());
  byId("contain-button").addEventListener("click", containSelected);
});
