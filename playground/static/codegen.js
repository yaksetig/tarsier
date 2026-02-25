// codegen.js — generateTRS(model) produces syntactically correct .trs text

function generateTRS(model) {
  const lines = [];
  lines.push(`protocol ${model.name} {`);

  // Enums
  for (const e of model.enums || []) {
    lines.push(`    enum ${e.name} { ${e.variants.join(", ")} }`);
  }

  // Parameters
  if (model.params.length > 0) {
    const paramNames = model.params.map(p => p.name).join(", ");
    lines.push(`    params ${paramNames};`);
  }

  // Resilience
  if (model.resilience) {
    lines.push(`    resilience: ${model.resilience};`);
  }

  // Pacemaker
  if (model.pacemaker) {
    const pm = model.pacemaker;
    lines.push(`    pacemaker {`);
    lines.push(`        view: ${pm.viewVar};`);
    lines.push(`        start_phase: ${pm.startPhase};`);
    if (pm.resetVars && pm.resetVars.length > 0) {
      lines.push(`        reset: ${pm.resetVars.join(", ")};`);
    }
    lines.push(`    }`);
  }

  // Adversary
  if (model.adversary.length > 0) {
    lines.push(`    adversary {`);
    for (const a of model.adversary) {
      lines.push(`        ${a.key}: ${a.value};`);
    }
    lines.push(`    }`);
  }

  // Identities
  for (const id of model.identities || []) {
    let decl = `    identity ${id.role}: ${id.scope}`;
    if (id.processVar) decl += ` ${id.processVar}`;
    if (id.key) decl += ` key ${id.key}`;
    lines.push(decl + ";");
  }

  // Channels
  for (const ch of model.channels || []) {
    lines.push(`    channel ${ch.message}: ${ch.auth};`);
  }

  // Equivocation policies
  for (const eq of model.equivocationPolicies || []) {
    lines.push(`    equivocation ${eq.message}: ${eq.mode};`);
  }

  // Committees
  for (const c of model.committees || []) {
    lines.push(`    committee ${c.name} {`);
    for (const item of c.items || []) {
      lines.push(`        ${item.key}: ${item.value};`);
    }
    lines.push(`    }`);
  }

  // Messages
  for (const m of model.messages) {
    const fields = m.fields.map(f => {
      let decl = `${f.name}: ${f.ty}`;
      if (f.range) decl += ` in ${f.range.min}..${f.range.max}`;
      return decl;
    }).join(", ");
    lines.push(`    message ${m.name}(${fields});`);
  }

  // Crypto objects
  for (const co of model.cryptoObjects || []) {
    const kindStr = co.kind === "QuorumCertificate" ? "certificate" : "threshold_signature";
    let decl = `    ${kindStr} ${co.name} from ${co.sourceMessage} threshold ${co.threshold}`;
    if (co.signerRole) decl += ` signer ${co.signerRole}`;
    if (co.conflictPolicy === "Exclusive") decl += ` conflict exclusive`;
    lines.push(decl + ";");
  }

  // Blank line before roles
  lines.push("");

  // Roles
  for (const role of model.roles) {
    lines.push(`    role ${role.name} {`);

    // Variables
    for (const v of role.vars) {
      let decl = `        var ${v.name}: ${v.ty}`;
      if (v.range) decl += ` in ${v.range.min}..${v.range.max}`;
      if (v.init !== null && v.init !== undefined) decl += ` = ${v.init}`;
      lines.push(decl + ";");
    }

    // Init phase
    if (role.initPhase) {
      lines.push(`        init ${role.initPhase};`);
    }

    // Blank line before phases
    lines.push("");

    // Phases
    for (const phase of role.phases) {
      if (phase.transitions.length === 0) {
        lines.push(`        phase ${phase.name} {}`);
      } else {
        lines.push(`        phase ${phase.name} {`);
        for (const tr of phase.transitions) {
          const actionsStr = tr.actions.map(a => actionToTRS(a)).join(" ");
          lines.push(`            when ${tr.guardText} => { ${actionsStr} }`);
        }
        lines.push(`        }`);
      }
    }
    lines.push(`    }`);
  }

  // Blank line before properties
  lines.push("");

  // Properties
  for (const prop of model.properties) {
    lines.push(`    property ${prop.name}: ${prop.kind} {`);
    lines.push(`        ${prop.formulaText}`);
    lines.push(`    }`);
  }

  lines.push("}");
  return lines.join("\n") + "\n";
}

function actionToTRS(action) {
  switch (action.type) {
    case "send": {
      const args = (action.data.args || []).join(", ");
      let s = `send ${action.data.messageType}(${args})`;
      if (action.data.recipientRole) s += ` to ${action.data.recipientRole}`;
      return s + ";";
    }
    case "form": {
      const args = (action.data.args || []).join(", ");
      let s = `form ${action.data.objectName}(${args})`;
      if (action.data.recipientRole) s += ` to ${action.data.recipientRole}`;
      return s + ";";
    }
    case "lock": {
      const args = (action.data.args || []).join(", ");
      return `lock ${action.data.objectName}(${args});`;
    }
    case "justify": {
      const args = (action.data.args || []).join(", ");
      return `justify ${action.data.objectName}(${args});`;
    }
    case "assign":
      return `${action.data.var} = ${action.data.value};`;
    case "goto":
      return `goto ${action.data.phase};`;
    case "decide":
      return `decide ${action.data.value};`;
    default:
      return `/* unknown action: ${action.type} */`;
  }
}
