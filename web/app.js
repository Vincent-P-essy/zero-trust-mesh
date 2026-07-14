"use strict";

async function api(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) throw new Error(`${path} -> ${response.status}`);
  return response.json();
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function badge(value) {
  const node = el("span", `badge ${value}`, value.replace(/_/g, " "));
  return node;
}

function renderTimeline(session) {
  const container = document.getElementById("timeline");
  container.innerHTML = "";
  if (!session || !session.timeline) {
    container.appendChild(el("p", "hint", "No session events."));
    return;
  }
  const head = el("p", "hint");
  head.append(
    `Session ${session.session_id} - ${session.permitted} permitted, ${session.denied} denied, final state `
  );
  head.appendChild(badge(session.state));
  container.appendChild(head);
  for (const event of session.timeline) {
    const row = el("div", "event");
    row.appendChild(el("span", "seq", `t+${Math.round(event.at_epoch)}s`));
    const middle = el("div");
    middle.appendChild(el("div", "reason", `${event.resource} - ${event.reason}`));
    const meter = el("div", "meter");
    const fill = el("span");
    fill.style.width = `${event.trust_score}%`;
    meter.appendChild(fill);
    middle.appendChild(meter);
    row.appendChild(middle);
    row.appendChild(badge(event.effect));
    container.appendChild(row);
  }
}

async function loadScenarios() {
  const data = await api("/scenarios");
  const list = document.getElementById("scenarios");
  list.innerHTML = "";
  for (const scenario of data.scenarios) {
    const card = el("button", "scenario");
    card.type = "button";
    card.appendChild(el("div", "name", scenario.name));
    card.appendChild(el("div", "desc", scenario.description));
    card.addEventListener("click", async () => {
      const result = await api(`/scenarios/${scenario.name}/run`, { method: "POST" });
      renderTimeline(result.timeline);
    });
    list.appendChild(card);
  }
}

function option(value, label) {
  const node = el("option", null, label || value);
  node.value = value;
  return node;
}

async function loadMesh() {
  const mesh = await api("/mesh");
  document.getElementById("mesh-meta").textContent = `${mesh.name} - trust domain ${mesh.trust_domain}`;
  const principal = document.getElementById("principal");
  const device = document.getElementById("device");
  const resource = document.getElementById("resource");
  for (const p of mesh.principals) principal.appendChild(option(p.id, `${p.id} (${p.kind})`));
  for (const d of mesh.devices) device.appendChild(option(d.id, `${d.id}`));
  for (const r of mesh.resources) resource.appendChild(option(r.id, `${r.id} (${r.sensitivity})`));
}

function renderDecision(decision) {
  const container = document.getElementById("decision");
  container.innerHTML = "";
  const head = el("div");
  head.appendChild(badge(decision.effect));
  head.append(` trust ${decision.trust_score.toFixed(1)}`);
  if (decision.matched_rule) head.append(` - rule ${decision.matched_rule}`);
  container.appendChild(head);
  if (decision.reasons.length) {
    container.appendChild(el("p", "hint", decision.reasons.join("; ")));
  }
  const factors = el("div", "factors");
  for (const factor of decision.trust_factors) {
    const row = el("div", "factor");
    row.appendChild(el("span", null, factor.name));
    row.appendChild(el("span", null, factor.detail));
    const value = el("span", `val ${factor.contribution >= 0 ? "pos" : "neg"}`);
    value.textContent = `${factor.contribution >= 0 ? "+" : ""}${factor.contribution}`;
    row.appendChild(value);
    factors.appendChild(row);
  }
  container.appendChild(factors);
}

async function submitRequest(event) {
  event.preventDefault();
  const body = {
    session_id: "explorer",
    principal_id: document.getElementById("principal").value,
    device_id: document.getElementById("device").value,
    resource_id: document.getElementById("resource").value,
    action: "read",
    assurance: document.getElementById("assurance").value,
    network: {
      country: "FR",
      corporate: document.getElementById("corporate").checked,
      tor_exit: document.getElementById("tor").checked,
    },
  };
  const result = await api("/mesh/request", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  renderDecision(result.decision);
}

async function main() {
  await Promise.all([loadScenarios(), loadMesh()]);
  document.getElementById("request-form").addEventListener("submit", submitRequest);
}

main().catch((error) => {
  document.getElementById("subtitle").textContent = `Failed to load: ${error.message}`;
});
