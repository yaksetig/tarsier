const healthPill = document.getElementById("health-pill");
const runMeta = document.getElementById("run-meta");
const summaryBox = document.getElementById("result-summary");
const outputPre = document.getElementById("output-pre");
const jsonPre = document.getElementById("json-pre");
const lintPre = document.getElementById("lint-pre");
const traceView = document.getElementById("trace-view");
const ctiView = document.getElementById("cti-view");

const editor = document.getElementById("source-editor");
const exampleSelect = document.getElementById("example-select");
const workflowSelect = document.getElementById("workflow-select");
const advancedToggle = document.getElementById("advanced-toggle");
const checkSelect = document.getElementById("check-select");
const assistKindSelect = document.getElementById("assist-kind-select");
const solverSelect = document.getElementById("solver-select");
const proofEngineSelect = document.getElementById("proof-engine-select");
const fairnessSelect = document.getElementById("fairness-select");
const depthInput = document.getElementById("depth-input");
const timeoutInput = document.getElementById("timeout-input");
const soundnessSelect = document.getElementById("soundness-select");

const loadExampleBtn = document.getElementById("load-example-btn");
const assistBtn = document.getElementById("assist-btn");
const formatBtn = document.getElementById("format-btn");
const lintBtn = document.getElementById("lint-btn");
const runBtn = document.getElementById("run-btn");
const exportJsonBtn = document.getElementById("export-json-btn");
const exportMarkdownBtn = document.getElementById("export-markdown-btn");
const exportTimelineBtn = document.getElementById("export-timeline-btn");
const exportMermaidBtn = document.getElementById("export-mermaid-btn");
const exportBundleBtn = document.getElementById("export-bundle-btn");

const tabs = Array.from(document.querySelectorAll(".tab"));
const panes = Array.from(document.querySelectorAll(".pane"));
const advancedControls = Array.from(document.querySelectorAll(".advanced-control"));

let latestRunPayload = null;
let latestRunRequest = null;
let latestLintIssues = [];

let examples = [];

init().catch((error) => {
  console.error(error);
  setSummary("Failed to initialize playground.", "unknown");
});

async function init() {
  await checkHealth();
  await loadExamples();
  wireEvents();
  applyWorkflowPreset(workflowSelect.value || "standard", false);
  updateControlVisibility();
  clearResult();
  updateExportButtons();
}

function wireEvents() {
  checkSelect.addEventListener("change", updateControlVisibility);
  workflowSelect.addEventListener("change", () => {
    applyWorkflowPreset(workflowSelect.value || "standard", true);
    updateControlVisibility();
  });
  advancedToggle.addEventListener("change", updateControlVisibility);

  loadExampleBtn.addEventListener("click", () => {
    const selected = examples.find((item) => item.id === exampleSelect.value);
    if (!selected) {
      return;
    }
    editor.value = selected.source;
    setSummary(`Loaded example: ${selected.name}.`, "unknown");
  });

  assistBtn.addEventListener("click", async () => {
    await insertAssistTemplate();
  });

  formatBtn.addEventListener("click", () => {
    editor.value = normalizeEditor(editor.value);
    setSummary("Editor spacing normalized.", "unknown");
  });

  lintBtn.addEventListener("click", async () => {
    await runLint();
  });

  runBtn.addEventListener("click", async () => {
    await runAnalysis();
  });

  exportJsonBtn.addEventListener("click", exportJsonReport);
  exportMarkdownBtn.addEventListener("click", exportMarkdownReport);
  exportTimelineBtn.addEventListener("click", exportTimeline);
  exportMermaidBtn.addEventListener("click", exportMermaid);
  exportBundleBtn.addEventListener("click", exportArtifactBundle);

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => t.classList.remove("active"));
      panes.forEach((p) => p.classList.remove("active"));
      tab.classList.add("active");
      const paneId = tab.dataset.pane;
      const pane = document.getElementById(paneId);
      if (pane) {
        pane.classList.add("active");
      }
    });
  });
}

async function insertAssistTemplate() {
  const kind = (assistKindSelect.value || "pbft").trim().toLowerCase();
  assistBtn.disabled = true;
  runMeta.textContent = `Generating ${kind} scaffold...`;
  runMeta.style.color = "#9cb9cb";

  try {
    const response = await fetch("/api/assist", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ kind }),
    });
    const payload = await response.json();
    if (!response.ok || payload.ok === false) {
      throw new Error(payload.error || "failed to generate scaffold");
    }
    editor.value = payload.source || "";
    runMeta.textContent = `Scaffold ready (${kind})`;
    runMeta.style.color = "#3ad29f";
    setSummary(`Inserted ${kind} scaffold template.`, "ok");
  } catch (error) {
    runMeta.textContent = "Scaffold error";
    runMeta.style.color = "#ff7b78";
    setSummary(error.message || "failed to generate scaffold", "fail");
  } finally {
    assistBtn.disabled = false;
  }
}

function setSelectValue(select, value) {
  if (!select) {
    return;
  }
  if (Array.from(select.options || []).some((option) => option.value === value)) {
    select.value = value;
  }
}

function applyWorkflowPreset(mode, announce) {
  const presets = {
    quick: {
      check: "verify",
      solver: "z3",
      proofEngine: "kinduction",
      fairness: "weak",
      depth: 8,
      timeout: 30,
      soundness: "strict",
    },
    standard: {
      check: "fair-liveness",
      solver: "z3",
      proofEngine: "pdr",
      fairness: "weak",
      depth: 12,
      timeout: 90,
      soundness: "strict",
    },
    proof: {
      check: "prove-fair",
      solver: "z3",
      proofEngine: "pdr",
      fairness: "strong",
      depth: 16,
      timeout: 180,
      soundness: "strict",
    },
  };
  const preset = presets[mode] || presets.standard;
  setSelectValue(checkSelect, preset.check);
  setSelectValue(solverSelect, preset.solver);
  setSelectValue(proofEngineSelect, preset.proofEngine);
  setSelectValue(fairnessSelect, preset.fairness);
  setSelectValue(soundnessSelect, preset.soundness);
  depthInput.value = String(preset.depth);
  timeoutInput.value = String(preset.timeout);
  if (announce) {
    setSummary(`Applied ${mode} workflow defaults.`, "unknown");
  }
}

function updateControlVisibility() {
  const check = checkSelect.value;
  const showAdvanced = Boolean(advancedToggle.checked);
  const showProofEngine = check === "prove";
  const showFairness = check === "fair-liveness" || check === "prove-fair";
  for (const field of advancedControls) {
    field.style.display = showAdvanced ? "grid" : "none";
  }
  proofEngineSelect.closest(".field").style.display =
    showAdvanced && showProofEngine ? "grid" : "none";
  fairnessSelect.closest(".field").style.display =
    showAdvanced && showFairness ? "grid" : "none";
}

async function checkHealth() {
  try {
    const response = await fetch("/api/health");
    const payload = await response.json();
    if (!response.ok || !payload.ok) {
      throw new Error("health check failed");
    }
    healthPill.textContent = "API Ready";
    healthPill.style.color = "#3ad29f";
  } catch (error) {
    healthPill.textContent = "API Unavailable";
    healthPill.style.color = "#ff7b78";
  }
}

async function loadExamples() {
  const response = await fetch("/api/examples");
  const payload = await response.json();

  if (!response.ok || !Array.isArray(payload)) {
    throw new Error("could not load examples");
  }

  examples = payload;
  exampleSelect.innerHTML = "";
  for (const example of examples) {
    const option = document.createElement("option");
    option.value = example.id;
    option.textContent = example.name;
    exampleSelect.appendChild(option);
  }

  if (examples.length > 0) {
    editor.value = examples[0].source;
  }
}

async function runLint() {
  const source = editor.value;
  if (!source.trim()) {
    setSummary("Protocol source is empty.", "fail");
    return;
  }

  lintBtn.disabled = true;
  runMeta.textContent = "Linting...";

  try {
    const response = await fetch("/api/lint", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        source,
        filename: `${exampleSelect.value || "playground"}.trs`,
      }),
    });
    const payload = await response.json();

    if (!response.ok || payload.ok === false && !Array.isArray(payload.issues)) {
      throw new Error(payload.error || "lint failed");
    }

    const rendered = renderLint(payload.issues || []);
    latestLintIssues = Array.isArray(payload.issues) ? payload.issues : [];
    lintPre.textContent = rendered;
    runMeta.textContent = "Lint complete";
    runMeta.style.color = payload.ok ? "#3ad29f" : "#f0b565";

    if ((payload.issues || []).length === 0) {
      setSummary("Lint passed with no issues.", "ok");
    } else if ((payload.issues || []).some((issue) => issue.severity === "error")) {
      setSummary("Lint found blocking issues.", "fail");
    } else {
      setSummary("Lint found warnings/info.", "unknown");
    }

    activateTab("lint-pane");
  } catch (error) {
    runMeta.textContent = "Lint error";
    runMeta.style.color = "#ff7b78";
    setSummary(error.message || "lint failed", "fail");
    lintPre.textContent = String(error);
    latestLintIssues = [];
  } finally {
    lintBtn.disabled = false;
  }
}

async function runAnalysis() {
  const source = editor.value;
  if (!source.trim()) {
    setSummary("Protocol source is empty.", "fail");
    return;
  }

  const request = {
    source,
    check: checkSelect.value,
    filename: `${exampleSelect.value || "playground"}.trs`,
    solver: solverSelect.value,
    depth: Number(depthInput.value),
    timeout_secs: Number(timeoutInput.value),
    soundness: soundnessSelect.value,
    proof_engine: proofEngineSelect.value,
    fairness: fairnessSelect.value,
  };

  runBtn.disabled = true;
  runMeta.textContent = "Running...";
  clearResult();
  latestRunPayload = null;
  latestRunRequest = null;
  updateExportButtons();

  try {
    const startedAt = performance.now();
    const response = await fetch("/api/run", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    const payload = await response.json();
    const elapsedMs = Math.round(performance.now() - startedAt);

    if (!response.ok || payload.ok === false) {
      const message = payload.error || "analysis failed";
      throw new Error(message);
    }

    runMeta.textContent = `${payload.result} in ${elapsedMs}ms`;
    runMeta.style.color = payload.ok ? "#3ad29f" : "#f0b565";
    setSummary(payload.summary, classifyResult(payload.result));
    latestRunPayload = payload;
    latestRunRequest = request;

    outputPre.textContent = payload.output || "";
    jsonPre.textContent = JSON.stringify(payload, null, 2);
    renderTrace(payload.trace, payload.mermaid, payload.timeline);
    renderCti(payload.cti);
    updateExportButtons();
  } catch (error) {
    runMeta.textContent = "Error";
    runMeta.style.color = "#ff7b78";
    setSummary(error.message || "analysis failed", "fail");
    outputPre.textContent = String(error);
    jsonPre.textContent = "";
    traceView.innerHTML = "";
    ctiView.innerHTML = "";
    latestRunPayload = null;
    latestRunRequest = null;
    updateExportButtons();
  } finally {
    runBtn.disabled = false;
  }
}

function classifyResult(result) {
  if (["safe", "probabilistically_safe", "live", "live_proved", "no_fair_cycle"].includes(result)) {
    return "ok";
  }
  if (["unknown", "not_proved"].includes(result)) {
    return "unknown";
  }
  return "fail";
}

function setSummary(text, mode) {
  summaryBox.textContent = text;
  summaryBox.classList.remove("summary-ok", "summary-fail", "summary-unknown");
  if (mode === "ok") {
    summaryBox.classList.add("summary-ok");
  } else if (mode === "fail") {
    summaryBox.classList.add("summary-fail");
  } else {
    summaryBox.classList.add("summary-unknown");
  }
}

function clearResult() {
  outputPre.textContent = "";
  jsonPre.textContent = "";
  lintPre.textContent = "";
  traceView.innerHTML = "";
  ctiView.innerHTML = "";
}

function renderTrace(trace, mermaidSrc, timelineSrc) {
  traceView.innerHTML = "";
  if (!trace) {
    traceView.textContent = "No trace available for this result.";
    return;
  }

  const wrapper = document.createElement("div");

  // Timeline text block
  if (timelineSrc) {
    const timelineHeader = document.createElement("h3");
    timelineHeader.textContent = "Timeline";
    timelineHeader.style.color = "#9cb9cb";
    timelineHeader.style.marginBottom = "4px";
    wrapper.appendChild(timelineHeader);
    const timelinePre = document.createElement("pre");
    timelinePre.textContent = timelineSrc;
    timelinePre.style.maxHeight = "300px";
    timelinePre.style.overflow = "auto";
    wrapper.appendChild(timelinePre);
  }

  // Mermaid MSC diagram
  if (mermaidSrc && typeof mermaid !== "undefined") {
    const mscHeader = document.createElement("h3");
    mscHeader.textContent = "Message Sequence Chart";
    mscHeader.style.color = "#9cb9cb";
    mscHeader.style.marginBottom = "4px";
    wrapper.appendChild(mscHeader);
    const mermaidDiv = document.createElement("pre");
    mermaidDiv.className = "mermaid";
    mermaidDiv.textContent = mermaidSrc;
    wrapper.appendChild(mermaidDiv);
  } else if (mermaidSrc) {
    // Fallback: show raw mermaid source
    const mscHeader = document.createElement("h3");
    mscHeader.textContent = "Message Sequence Chart (Mermaid source)";
    mscHeader.style.color = "#9cb9cb";
    mscHeader.style.marginBottom = "4px";
    wrapper.appendChild(mscHeader);
    const mermaidPre = document.createElement("pre");
    mermaidPre.textContent = mermaidSrc;
    mermaidPre.style.maxHeight = "300px";
    mermaidPre.style.overflow = "auto";
    wrapper.appendChild(mermaidPre);
  }

  const params = document.createElement("pre");
  const paramLines = (trace.params || [])
    .map(([name, value]) => `${name} = ${value}`)
    .join("\n");
  params.textContent = paramLines ? `Parameters:\n${paramLines}` : "Parameters: (none)";
  wrapper.appendChild(params);

  const replay = document.createElement("div");
  replay.className = "trace-replay";
  const slider = document.createElement("input");
  slider.type = "range";
  slider.min = "0";
  slider.max = String((trace.steps || []).length);
  slider.step = "1";
  slider.value = "0";
  const label = document.createElement("div");
  label.style.color = "#9cb9cb";
  label.style.fontSize = "12px";

  replay.appendChild(label);
  replay.appendChild(slider);
  wrapper.appendChild(replay);

  const stateCard = document.createElement("pre");
  stateCard.className = "trace-state";
  wrapper.appendChild(stateCard);

  const table = document.createElement("table");
  table.className = "trace-table";
  table.innerHTML = `
    <thead>
      <tr>
        <th>Step</th>
        <th>Rule</th>
        <th>Delta</th>
        <th>kappa</th>
        <th>gamma</th>
      </tr>
    </thead>
    <tbody></tbody>
  `;

  const body = table.querySelector("tbody");
  for (const step of trace.steps || []) {
    const row = document.createElement("tr");
    row.dataset.stepIndex = String(step.index);
    row.innerHTML = `
      <td>${step.index}</td>
      <td>r${step.rule_id}</td>
      <td>${step.delta}</td>
      <td>${formatArray(step.kappa)}</td>
      <td>${formatArray(step.gamma)}</td>
    `;
    body.appendChild(row);
  }

  wrapper.appendChild(table);
  traceView.appendChild(wrapper);

  function updateReplay() {
    const stepIndex = Number(slider.value);
    const stepCount = (trace.steps || []).length;

    for (const row of body.querySelectorAll("tr")) {
      const idx = Number(row.dataset.stepIndex || "0");
      row.style.background = idx === stepIndex ? "rgba(78,197,255,0.15)" : "transparent";
    }

    if (stepIndex === 0) {
      label.textContent = `State at step 0 (initial)`;
      const initial = trace.initial || { kappa: [], gamma: [] };
      stateCard.textContent = [
        "Initial configuration",
        `kappa = ${formatArray(initial.kappa || [])}`,
        `gamma = ${formatArray(initial.gamma || [])}`,
      ].join("\n");
      return;
    }

    const step = trace.steps[stepIndex - 1];
    if (!step) {
      label.textContent = `State at step ${stepCount}`;
      return;
    }
    label.textContent = `State at step ${stepIndex} (after r${step.rule_id}, delta=${step.delta})`;
    stateCard.textContent = [
      `After rule r${step.rule_id}, delta=${step.delta}`,
      `kappa = ${formatArray(step.kappa || [])}`,
      `gamma = ${formatArray(step.gamma || [])}`,
    ].join("\n");
  }

  slider.addEventListener("input", updateReplay);
  updateReplay();

  // Render mermaid diagrams after DOM insert
  if (mermaidSrc && typeof mermaid !== "undefined") {
    try {
      mermaid.run({ nodes: wrapper.querySelectorAll(".mermaid") });
    } catch (_) {
      // mermaid rendering is best-effort
    }
  }
}

function renderCti(cti) {
  ctiView.innerHTML = "";
  if (!cti) {
    ctiView.textContent = "No CTI available.";
    return;
  }

  const pre = document.createElement("pre");
  const lines = [];
  lines.push(`k = ${cti.k}`);
  lines.push("");
  lines.push("Parameters:");
  lines.push(...formatNamedRows(cti.params));
  lines.push("");
  lines.push("Hypothesis state (k-1):");
  lines.push(...formatNamedRows(cti.hypothesis_locations));
  lines.push(...formatNamedRows(cti.hypothesis_shared));
  lines.push("");
  lines.push("Violating state (k):");
  lines.push(...formatNamedRows(cti.violating_locations));
  lines.push(...formatNamedRows(cti.violating_shared));
  lines.push("");
  lines.push("Final step rules:");
  lines.push(...formatNamedRows(cti.final_step_rules));
  lines.push("");
  lines.push(`Violated condition: ${cti.violated_condition}`);

  pre.textContent = lines.join("\n");
  ctiView.appendChild(pre);
}

function updateExportButtons() {
  const hasRun = Boolean(latestRunPayload);
  const hasTimeline = Boolean(latestRunPayload && latestRunPayload.timeline);
  const hasMermaid = Boolean(latestRunPayload && latestRunPayload.mermaid);
  exportJsonBtn.disabled = !hasRun;
  exportMarkdownBtn.disabled = !hasRun;
  exportBundleBtn.disabled = !hasRun;
  exportTimelineBtn.disabled = !hasTimeline;
  exportMermaidBtn.disabled = !hasMermaid;
}

function downloadText(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType || "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function downloadStamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function artifactBaseName() {
  const sourceName = (exampleSelect.value || "playground").replace(/[^A-Za-z0-9_-]/g, "_");
  return `${sourceName}-${downloadStamp()}`;
}

function exportJsonReport() {
  if (!latestRunPayload) {
    return;
  }
  const name = `${artifactBaseName()}-report.json`;
  downloadText(name, JSON.stringify(latestRunPayload, null, 2), "application/json");
}

function buildMarkdownReport() {
  if (!latestRunPayload) {
    return "";
  }
  const lines = [];
  lines.push("# Tarsier Analysis Report");
  lines.push("");
  lines.push(`- Workflow: ${workflowSelect.value || "standard"}`);
  lines.push(`- Check: ${latestRunPayload.check || latestRunRequest?.check || "unknown"}`);
  lines.push(`- Result: ${latestRunPayload.result || "unknown"}`);
  lines.push(`- Summary: ${latestRunPayload.summary || ""}`);
  lines.push("");
  lines.push("## Request");
  lines.push("```json");
  lines.push(JSON.stringify(latestRunRequest || {}, null, 2));
  lines.push("```");
  lines.push("");
  lines.push("## Engine Output");
  lines.push("```text");
  lines.push(latestRunPayload.output || "");
  lines.push("```");
  if (latestRunPayload.timeline) {
    lines.push("");
    lines.push("## Timeline");
    lines.push("```text");
    lines.push(latestRunPayload.timeline);
    lines.push("```");
  }
  if (latestRunPayload.mermaid) {
    lines.push("");
    lines.push("## Message Sequence Chart");
    lines.push("```mermaid");
    lines.push(latestRunPayload.mermaid);
    lines.push("```");
  }
  if (latestRunPayload.trace) {
    lines.push("");
    lines.push("## Trace JSON");
    lines.push("```json");
    lines.push(JSON.stringify(latestRunPayload.trace, null, 2));
    lines.push("```");
  }
  return lines.join("\n");
}

function exportMarkdownReport() {
  if (!latestRunPayload) {
    return;
  }
  const name = `${artifactBaseName()}-report.md`;
  downloadText(name, buildMarkdownReport(), "text/markdown;charset=utf-8");
}

function exportTimeline() {
  if (!latestRunPayload || !latestRunPayload.timeline) {
    return;
  }
  const name = `${artifactBaseName()}-timeline.txt`;
  downloadText(name, latestRunPayload.timeline, "text/plain;charset=utf-8");
}

function exportMermaid() {
  if (!latestRunPayload || !latestRunPayload.mermaid) {
    return;
  }
  const name = `${artifactBaseName()}-msc.mmd`;
  downloadText(name, latestRunPayload.mermaid, "text/plain;charset=utf-8");
}

function exportArtifactBundle() {
  if (!latestRunPayload) {
    return;
  }
  const bundle = {
    schema_version: 1,
    exported_at: new Date().toISOString(),
    source: editor.value,
    request: latestRunRequest,
    run: latestRunPayload,
    lint_issues: latestLintIssues,
    markdown_report: buildMarkdownReport(),
  };
  const name = `${artifactBaseName()}-bundle.json`;
  downloadText(name, JSON.stringify(bundle, null, 2), "application/json");
}

function renderLint(issues) {
  if (!issues || issues.length === 0) {
    return "No lint issues.";
  }
  const lines = ["Lint issues:", ""];
  for (const issue of issues) {
    lines.push(`[${(issue.severity || "info").toUpperCase()}] ${issue.code}: ${issue.message}`);
    if (issue.source_span) {
      const span = issue.source_span;
      lines.push(
        `    span: ${span.line}:${span.column} -> ${span.end_line}:${span.end_column} (bytes ${span.start}..${span.end})`
      );
    }
    if (issue.suggestion) {
      lines.push(`    suggestion: ${issue.suggestion}`);
    }
  }
  return lines.join("\n");
}

function formatNamedRows(rows) {
  if (!rows || rows.length === 0) {
    return ["  (none)"];
  }
  return rows.map((row) => `  ${row.name}: ${row.value}`);
}

function formatArray(value) {
  if (!Array.isArray(value)) {
    return "[]";
  }
  return `[${value.join(", ")}]`;
}

function activateTab(paneId) {
  tabs.forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.pane === paneId);
  });
  panes.forEach((pane) => {
    pane.classList.toggle("active", pane.id === paneId);
  });
}

function normalizeEditor(source) {
  return source
    .split("\n")
    .map((line) => line.replace(/\s+$/g, ""))
    .join("\n")
    .replace(/\n{3,}/g, "\n\n");
}
