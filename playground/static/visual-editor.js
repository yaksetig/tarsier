// visual-editor.js — Cytoscape canvas, graph rendering, inspector panel, node/edge editing

let cy = null;
let currentModel = null;
let currentRoleIndex = 0;
let edgehandles = null;

const CY_NODE_STYLE = {
  "background-color": "#0c2330",
  "border-width": 2,
  "border-color": "#4ec5ff",
  label: "data(label)",
  "text-valign": "center",
  "text-halign": "center",
  color: "#e8f4ff",
  "font-size": "13px",
  "font-family": "SFMono-Regular, Menlo, Consolas, monospace",
  shape: "roundrectangle",
  width: "label",
  height: "label",
  padding: "14px",
};

const CY_INIT_NODE_STYLE = {
  "border-color": "#3ad29f",
  "border-width": 3,
};

const CY_EDGE_STYLE = {
  "curve-style": "bezier",
  "target-arrow-shape": "triangle",
  "target-arrow-color": "#4ec5ff",
  "line-color": "#4ec5ff",
  "line-opacity": 0.7,
  width: 2,
  label: "data(label)",
  color: "#9cb9cb",
  "font-size": "11px",
  "font-family": "SFMono-Regular, Menlo, Consolas, monospace",
  "text-rotation": "autorotate",
  "text-margin-y": -10,
  "text-background-color": "#0c2330",
  "text-background-opacity": 0.8,
  "text-background-padding": "3px",
};

const CY_SELF_LOOP_STYLE = {
  "curve-style": "bezier",
  "control-point-step-size": 60,
  "loop-direction": "0deg",
  "loop-sweep": "-60deg",
};

function initVisualEditor() {
  const container = document.getElementById("cy-canvas");
  if (!container) return;

  cy = cytoscape({
    container,
    style: [
      { selector: "node", style: CY_NODE_STYLE },
      { selector: "node.init-phase", style: CY_INIT_NODE_STYLE },
      { selector: "edge", style: CY_EDGE_STYLE },
      { selector: "edge.self-loop", style: CY_SELF_LOOP_STYLE },
      { selector: "node:selected", style: { "border-color": "#f0b565", "border-width": 3 } },
      { selector: "edge:selected", style: { "line-color": "#f0b565", "target-arrow-color": "#f0b565", width: 3 } },
      { selector: ".eh-handle", style: { "background-color": "#4ec5ff", width: 12, height: 12, shape: "ellipse", "overlay-opacity": 0 } },
      { selector: ".eh-source", style: { "border-color": "#3ad29f", "border-width": 3 } },
      { selector: ".eh-target", style: { "border-color": "#3ad29f", "border-width": 3 } },
      { selector: ".eh-preview, .eh-ghost-edge", style: { "line-color": "#3ad29f", "target-arrow-color": "#3ad29f", opacity: 0.7 } },
    ],
    layout: { name: "preset" },
    minZoom: 0.3,
    maxZoom: 3,
  });

  // Initialize edgehandles
  if (typeof cy.edgehandles === "function") {
    edgehandles = cy.edgehandles({
      snap: true,
      noEdgeEventsInDraw: true,
      disableBrowserGestures: true,
      handlePosition: () => "right middle",
      edgeParams: (source, target) => ({
        data: { label: "", sourcePhase: source.id(), targetPhase: target.id() },
      }),
      complete: (sourceNode, targetNode, addedEdge) => {
        onEdgeDrawn(sourceNode, targetNode, addedEdge);
      },
    });
    edgehandles.disableDrawMode();
  }

  cy.on("tap", "node", (evt) => {
    const nodeId = evt.target.id();
    showNodeInspector(nodeId);
  });

  cy.on("tap", "edge", (evt) => {
    const edgeId = evt.target.id();
    showEdgeInspector(edgeId);
  });

  cy.on("tap", (evt) => {
    if (evt.target === cy) {
      showProtocolInspector();
    }
  });

  wireVisualToolbar();
}

function wireVisualToolbar() {
  const addPhaseBtn = document.getElementById("add-phase-btn");
  const drawEdgeBtn = document.getElementById("draw-edge-btn");
  const autoLayoutBtn = document.getElementById("auto-layout-btn");
  const roleSelect = document.getElementById("visual-role-select");

  if (addPhaseBtn) {
    addPhaseBtn.addEventListener("click", () => {
      const name = prompt("Phase name:");
      if (!name || !name.trim()) return;
      addPhaseToModel(name.trim());
    });
  }

  if (drawEdgeBtn) {
    drawEdgeBtn.addEventListener("click", () => {
      if (!edgehandles) return;
      if (drawEdgeBtn.classList.contains("active")) {
        edgehandles.disableDrawMode();
        drawEdgeBtn.classList.remove("active");
        drawEdgeBtn.textContent = "Draw Edge";
      } else {
        edgehandles.enableDrawMode();
        drawEdgeBtn.classList.add("active");
        drawEdgeBtn.textContent = "Stop Drawing";
      }
    });
  }

  if (autoLayoutBtn) {
    autoLayoutBtn.addEventListener("click", runAutoLayout);
  }

  if (roleSelect) {
    roleSelect.addEventListener("change", () => {
      currentRoleIndex = Number(roleSelect.value) || 0;
      renderGraphFromModel();
    });
  }
}

function loadModelIntoVisualEditor(model) {
  currentModel = model;
  currentRoleIndex = 0;
  populateRoleSelector();
  renderGraphFromModel();
  showProtocolInspector();
}

function populateRoleSelector() {
  const roleSelect = document.getElementById("visual-role-select");
  if (!roleSelect || !currentModel) return;
  roleSelect.innerHTML = "";
  currentModel.roles.forEach((role, i) => {
    const opt = document.createElement("option");
    opt.value = String(i);
    opt.textContent = role.name;
    roleSelect.appendChild(opt);
  });
  roleSelect.value = String(currentRoleIndex);
}

function renderGraphFromModel() {
  if (!cy || !currentModel) return;
  cy.elements().remove();

  const role = currentModel.roles[currentRoleIndex];
  if (!role) return;

  const elements = [];

  // Add nodes for each phase
  for (const phase of role.phases) {
    const classes = (role.initPhase === phase.name) ? "init-phase" : "";
    elements.push({
      group: "nodes",
      data: { id: phase.id, label: phase.name, phaseName: phase.name },
      classes,
    });
  }

  // Add edges for transitions
  for (const phase of role.phases) {
    for (const tr of phase.transitions) {
      const sourceId = phase.id;
      let targetId = sourceId; // self-loop by default
      if (tr.targetPhase) {
        const targetPhase = role.phases.find(p => p.name === tr.targetPhase);
        if (targetPhase) targetId = targetPhase.id;
      }
      const label = shortGuardLabel(tr.guardText);
      const classes = sourceId === targetId ? "self-loop" : "";
      elements.push({
        group: "edges",
        data: {
          id: tr.id,
          source: sourceId,
          target: targetId,
          label,
          transitionId: tr.id,
        },
        classes,
      });
    }
  }

  cy.add(elements);
  runAutoLayout();
}

function runAutoLayout() {
  if (!cy || cy.elements().length === 0) return;
  cy.layout({
    name: "dagre",
    rankDir: "LR",
    nodeSep: 60,
    rankSep: 80,
    padding: 30,
    animate: true,
    animationDuration: 300,
  }).run();
}

function shortGuardLabel(guardText) {
  if (!guardText) return "";
  // Shorten long guards for edge labels
  if (guardText.length <= 40) return guardText;
  // Try to extract the threshold part
  const match = guardText.match(/received\s+\S+\s+\S+\s+\w+/);
  if (match) return match[0];
  return guardText.substring(0, 37) + "...";
}

// --- Phase/Transition manipulation ---

function addPhaseToModel(name) {
  if (!currentModel) return;
  const role = currentModel.roles[currentRoleIndex];
  if (!role) return;
  if (role.phases.find(p => p.name === name)) {
    alert("Phase '" + name + "' already exists.");
    return;
  }
  const phase = new VisualPhase(name);
  role.phases.push(phase);
  renderGraphFromModel();
}

function deletePhase(phaseId) {
  if (!currentModel) return;
  const role = currentModel.roles[currentRoleIndex];
  if (!role) return;
  const idx = role.phases.findIndex(p => p.id === phaseId);
  if (idx < 0) return;
  const phaseName = role.phases[idx].name;
  // Remove transitions targeting this phase
  for (const phase of role.phases) {
    phase.transitions = phase.transitions.filter(t => t.targetPhase !== phaseName);
  }
  role.phases.splice(idx, 1);
  if (role.initPhase === phaseName) role.initPhase = role.phases.length > 0 ? role.phases[0].name : null;
  renderGraphFromModel();
  showProtocolInspector();
}

function setInitPhase(phaseId) {
  if (!currentModel) return;
  const role = currentModel.roles[currentRoleIndex];
  if (!role) return;
  const phase = role.phases.find(p => p.id === phaseId);
  if (!phase) return;
  role.initPhase = phase.name;
  renderGraphFromModel();
}

function onEdgeDrawn(sourceNode, targetNode, addedEdge) {
  if (!currentModel) return;
  const role = currentModel.roles[currentRoleIndex];
  if (!role) return;

  const sourcePhase = role.phases.find(p => p.id === sourceNode.id());
  if (!sourcePhase) { addedEdge.remove(); return; }

  const targetPhase = role.phases.find(p => p.id === targetNode.id());
  if (!targetPhase) { addedEdge.remove(); return; }

  const tr = new VisualTransition();
  tr.guardText = "true";
  if (sourcePhase.id !== targetPhase.id) {
    tr.actions.push(new VisualAction("goto", { phase: targetPhase.name }));
    tr.targetPhase = targetPhase.name;
  }
  sourcePhase.transitions.push(tr);

  // Re-render to get consistent IDs
  renderGraphFromModel();
}

function addTransitionToPhase(phaseId) {
  if (!currentModel) return;
  const role = currentModel.roles[currentRoleIndex];
  if (!role) return;
  const phase = role.phases.find(p => p.id === phaseId);
  if (!phase) return;
  const tr = new VisualTransition();
  tr.guardText = "true";
  phase.transitions.push(tr);
  renderGraphFromModel();
  showNodeInspector(phaseId);
}

function deleteTransition(phaseId, transitionId) {
  if (!currentModel) return;
  const role = currentModel.roles[currentRoleIndex];
  if (!role) return;
  const phase = role.phases.find(p => p.id === phaseId);
  if (!phase) return;
  phase.transitions = phase.transitions.filter(t => t.id !== transitionId);
  renderGraphFromModel();
  showNodeInspector(phaseId);
}

// --- Inspector Panel ---

function showProtocolInspector() {
  const panel = document.getElementById("inspector-panel");
  if (!panel || !currentModel) return;

  let html = '<div class="inspector-section">';
  html += '<h3 class="inspector-title">Protocol Configuration</h3>';
  html += `<div class="inspector-field"><label>Name</label><input type="text" value="${esc(currentModel.name)}" id="insp-proto-name" /></div>`;

  // Params
  html += `<div class="inspector-field"><label>Parameters</label><span class="inspector-value">${esc(currentModel.params.map(p => p.name).join(", "))}</span></div>`;

  // Resilience
  if (currentModel.resilience) {
    html += `<div class="inspector-field"><label>Resilience</label><span class="inspector-value">${esc(currentModel.resilience)}</span></div>`;
  }

  // Adversary
  if (currentModel.adversary.length > 0) {
    html += '<div class="inspector-field"><label>Adversary</label>';
    html += '<ul class="inspector-list">';
    for (const a of currentModel.adversary) {
      html += `<li>${esc(a.key)}: ${esc(a.value)}</li>`;
    }
    html += '</ul></div>';
  }

  // Messages
  if (currentModel.messages.length > 0) {
    html += '<div class="inspector-field"><label>Messages</label>';
    html += '<ul class="inspector-list">';
    for (const m of currentModel.messages) {
      const fields = m.fields.map(f => `${f.name}: ${f.ty}`).join(", ");
      html += `<li>${esc(m.name)}(${esc(fields)})</li>`;
    }
    html += '</ul></div>';
  }

  // Crypto objects
  if (currentModel.cryptoObjects.length > 0) {
    html += '<div class="inspector-field"><label>Crypto Objects</label>';
    html += '<ul class="inspector-list">';
    for (const co of currentModel.cryptoObjects) {
      html += `<li>${esc(co.name)}: ${esc(co.kind)} from ${esc(co.sourceMessage)}</li>`;
    }
    html += '</ul></div>';
  }

  // Properties
  if (currentModel.properties.length > 0) {
    html += '<div class="inspector-field"><label>Properties</label>';
    html += '<ul class="inspector-list">';
    for (const p of currentModel.properties) {
      html += `<li><strong>${esc(p.name)}</strong> (${esc(p.kind)}): ${esc(p.formulaText)}</li>`;
    }
    html += '</ul></div>';
  }

  html += '</div>';
  panel.innerHTML = html;

  const nameInput = document.getElementById("insp-proto-name");
  if (nameInput) {
    nameInput.addEventListener("change", () => {
      currentModel.name = nameInput.value.trim() || currentModel.name;
    });
  }
}

function showNodeInspector(nodeId) {
  const panel = document.getElementById("inspector-panel");
  if (!panel || !currentModel) return;
  const role = currentModel.roles[currentRoleIndex];
  if (!role) return;
  const phase = role.phases.find(p => p.id === nodeId);
  if (!phase) return;

  let html = '<div class="inspector-section">';
  html += `<h3 class="inspector-title">Phase: ${esc(phase.name)}</h3>`;
  html += `<div class="inspector-field"><label>Name</label><input type="text" value="${esc(phase.name)}" id="insp-phase-name" data-phase-id="${phase.id}" /></div>`;

  // Action buttons
  html += '<div class="inspector-actions">';
  if (role.initPhase !== phase.name) {
    html += `<button onclick="setInitPhase('${phase.id}')">Set as Init</button>`;
  } else {
    html += '<span class="inspector-badge">Init Phase</span>';
  }
  html += `<button class="inspector-btn-danger" onclick="if(confirm('Delete phase ${esc(phase.name)}?')) deletePhase('${phase.id}')">Delete Phase</button>`;
  html += '</div>';

  // Transitions
  html += '<div class="inspector-field"><label>Transitions</label></div>';
  for (let i = 0; i < phase.transitions.length; i++) {
    const tr = phase.transitions[i];
    const target = tr.targetPhase || "(self)";
    html += `<div class="inspector-transition">`;
    html += `<div class="inspector-transition-header">#${i + 1} → ${esc(target)}</div>`;
    html += `<div class="inspector-field"><label>Guard</label><input type="text" class="insp-guard-input" value="${esc(tr.guardText)}" data-phase-id="${phase.id}" data-tr-id="${tr.id}" /></div>`;

    // Actions
    html += '<div class="inspector-field"><label>Actions</label></div>';
    for (let j = 0; j < tr.actions.length; j++) {
      const act = tr.actions[j];
      html += `<div class="inspector-action">${esc(actionSummary(act))}</div>`;
    }

    html += `<button class="inspector-btn-small inspector-btn-danger" onclick="deleteTransition('${phase.id}', '${tr.id}')">Remove Transition</button>`;
    html += '</div>';
  }

  html += `<button class="inspector-btn-small" onclick="addTransitionToPhase('${phase.id}')">+ Add Transition</button>`;
  html += '</div>';
  panel.innerHTML = html;

  // Wire up name change
  const nameInput = document.getElementById("insp-phase-name");
  if (nameInput) {
    nameInput.addEventListener("change", () => {
      const newName = nameInput.value.trim();
      if (!newName || newName === phase.name) return;
      // Update references
      const oldName = phase.name;
      phase.name = newName;
      if (role.initPhase === oldName) role.initPhase = newName;
      for (const p of role.phases) {
        for (const t of p.transitions) {
          if (t.targetPhase === oldName) t.targetPhase = newName;
          for (const a of t.actions) {
            if (a.type === "goto" && a.data.phase === oldName) a.data.phase = newName;
          }
        }
      }
      renderGraphFromModel();
    });
  }

  // Wire up guard edits
  for (const input of panel.querySelectorAll(".insp-guard-input")) {
    input.addEventListener("change", () => {
      const trId = input.dataset.trId;
      const phId = input.dataset.phaseId;
      const ph = role.phases.find(p => p.id === phId);
      if (!ph) return;
      const t = ph.transitions.find(t => t.id === trId);
      if (!t) return;
      t.guardText = input.value;
      renderGraphFromModel();
    });
  }
}

function showEdgeInspector(edgeId) {
  const panel = document.getElementById("inspector-panel");
  if (!panel || !currentModel) return;
  const role = currentModel.roles[currentRoleIndex];
  if (!role) return;

  // Find the transition and its parent phase
  let foundPhase = null;
  let foundTransition = null;
  for (const phase of role.phases) {
    const tr = phase.transitions.find(t => t.id === edgeId);
    if (tr) {
      foundPhase = phase;
      foundTransition = tr;
      break;
    }
  }
  if (!foundPhase || !foundTransition) return;

  const tr = foundTransition;
  const target = tr.targetPhase || "(self)";

  let html = '<div class="inspector-section">';
  html += `<h3 class="inspector-title">Transition: ${esc(foundPhase.name)} → ${esc(target)}</h3>`;

  // Guard
  html += `<div class="inspector-field"><label>Guard Expression</label><input type="text" value="${esc(tr.guardText)}" id="insp-edge-guard" /></div>`;

  // Actions
  html += '<div class="inspector-field"><label>Actions</label></div>';
  for (let i = 0; i < tr.actions.length; i++) {
    const act = tr.actions[i];
    html += '<div class="inspector-action-edit">';
    html += `<select class="insp-action-type" data-idx="${i}">`;
    for (const type of ["send", "assign", "goto", "decide", "form", "lock", "justify"]) {
      const selected = type === act.type ? " selected" : "";
      html += `<option value="${type}"${selected}>${type}</option>`;
    }
    html += '</select>';
    html += `<input type="text" class="insp-action-detail" data-idx="${i}" value="${esc(actionDetailText(act))}" />`;
    html += `<button class="inspector-btn-tiny inspector-btn-danger" onclick="removeActionFromTransition('${foundPhase.id}', '${tr.id}', ${i})">x</button>`;
    html += '</div>';
  }

  html += `<button class="inspector-btn-small" onclick="addActionToTransition('${foundPhase.id}', '${tr.id}')">+ Add Action</button>`;
  html += `<button class="inspector-btn-small inspector-btn-danger" onclick="deleteTransition('${foundPhase.id}', '${tr.id}')">Delete Transition</button>`;
  html += '</div>';
  panel.innerHTML = html;

  // Wire guard edit
  const guardInput = document.getElementById("insp-edge-guard");
  if (guardInput) {
    guardInput.addEventListener("change", () => {
      tr.guardText = guardInput.value;
      renderGraphFromModel();
    });
  }

  // Wire action detail edits
  for (const input of panel.querySelectorAll(".insp-action-detail")) {
    input.addEventListener("change", () => {
      const idx = Number(input.dataset.idx);
      const act = tr.actions[idx];
      if (!act) return;
      updateActionFromText(act, input.value);
      renderGraphFromModel();
    });
  }

  // Wire action type changes
  for (const select of panel.querySelectorAll(".insp-action-type")) {
    select.addEventListener("change", () => {
      const idx = Number(select.dataset.idx);
      const act = tr.actions[idx];
      if (!act) return;
      act.type = select.value;
      act.data = {};
      showEdgeInspector(edgeId);
    });
  }
}

function addActionToTransition(phaseId, trId) {
  if (!currentModel) return;
  const role = currentModel.roles[currentRoleIndex];
  if (!role) return;
  const phase = role.phases.find(p => p.id === phaseId);
  if (!phase) return;
  const tr = phase.transitions.find(t => t.id === trId);
  if (!tr) return;
  tr.actions.push(new VisualAction("assign", { var: "x", value: "0" }));
  // Find the edge in cy and show its inspector
  showEdgeInspector(trId);
}

function removeActionFromTransition(phaseId, trId, actionIdx) {
  if (!currentModel) return;
  const role = currentModel.roles[currentRoleIndex];
  if (!role) return;
  const phase = role.phases.find(p => p.id === phaseId);
  if (!phase) return;
  const tr = phase.transitions.find(t => t.id === trId);
  if (!tr) return;
  tr.actions.splice(actionIdx, 1);
  // Update target phase if goto was removed
  const gotoAction = tr.actions.find(a => a.type === "goto");
  tr.targetPhase = gotoAction ? gotoAction.data.phase : null;
  renderGraphFromModel();
  showEdgeInspector(trId);
}

function actionSummary(act) {
  switch (act.type) {
    case "send": return `send ${act.data.messageType || "?"}(...)`;
    case "form": return `form ${act.data.objectName || "?"}(...)`;
    case "lock": return `lock ${act.data.objectName || "?"}(...)`;
    case "justify": return `justify ${act.data.objectName || "?"}(...)`;
    case "assign": return `${act.data.var || "?"} = ${act.data.value || "?"}`;
    case "goto": return `goto ${act.data.phase || "?"}`;
    case "decide": return `decide ${act.data.value || "?"}`;
    default: return act.type;
  }
}

function actionDetailText(act) {
  switch (act.type) {
    case "send": {
      const args = (act.data.args || []).join(", ");
      let s = `${act.data.messageType || "Msg"}(${args})`;
      if (act.data.recipientRole) s += ` to ${act.data.recipientRole}`;
      return s;
    }
    case "form": {
      const args = (act.data.args || []).join(", ");
      return `${act.data.objectName || "Obj"}(${args})`;
    }
    case "lock": {
      const args = (act.data.args || []).join(", ");
      return `${act.data.objectName || "Obj"}(${args})`;
    }
    case "justify": {
      const args = (act.data.args || []).join(", ");
      return `${act.data.objectName || "Obj"}(${args})`;
    }
    case "assign": return `${act.data.var || "x"} = ${act.data.value || "0"}`;
    case "goto": return act.data.phase || "?";
    case "decide": return act.data.value || "true";
    default: return "";
  }
}

function updateActionFromText(act, text) {
  text = text.trim();
  switch (act.type) {
    case "assign": {
      const eqIdx = text.indexOf("=");
      if (eqIdx >= 0) {
        act.data.var = text.substring(0, eqIdx).trim();
        act.data.value = text.substring(eqIdx + 1).trim();
      }
      break;
    }
    case "goto":
      act.data.phase = text;
      break;
    case "decide":
      act.data.value = text;
      break;
    case "send": {
      const match = text.match(/^(\w+)\(([^)]*)\)(?:\s+to\s+(\w+))?$/);
      if (match) {
        act.data.messageType = match[1];
        act.data.args = match[2] ? match[2].split(",").map(s => s.trim()) : [];
        act.data.recipientRole = match[3] || null;
      }
      break;
    }
    case "form":
    case "lock":
    case "justify": {
      const m = text.match(/^(\w+)\(([^)]*)\)/);
      if (m) {
        act.data.objectName = m[1];
        act.data.args = m[2] ? m[2].split(",").map(s => s.trim()) : [];
      }
      break;
    }
  }
}

function esc(s) {
  if (s === null || s === undefined) return "";
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function destroyVisualEditor() {
  if (cy) {
    cy.destroy();
    cy = null;
  }
  edgehandles = null;
  currentModel = null;
}
