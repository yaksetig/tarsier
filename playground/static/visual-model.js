// visual-model.js — VisualProtocolModel data model + fromAST() conversion

class VisualAction {
  constructor(type, data) {
    this.type = type;   // "send" | "assign" | "goto" | "decide" | "form" | "lock" | "justify"
    this.data = data || {};
  }
}

class VisualTransition {
  constructor() {
    this.id = crypto.randomUUID();
    this.guardText = "";
    this.actions = [];
    this.targetPhase = null; // null = self-loop (no goto)
  }
}

class VisualPhase {
  constructor(name) {
    this.id = crypto.randomUUID();
    this.name = name;
    this.transitions = [];
  }
}

class VisualRole {
  constructor(name) {
    this.name = name;
    this.vars = [];      // [{name, ty, range, init}]
    this.initPhase = null;
    this.phases = [];
  }
}

class VisualProtocolModel {
  constructor() {
    this.name = "";
    this.params = [];         // [{name, ty}]
    this.resilience = null;   // text string
    this.adversary = [];      // [{key, value}]
    this.enums = [];          // [{name, variants:[]}]
    this.identities = [];     // [{role, scope, processVar, key}]
    this.channels = [];       // [{message, auth}]
    this.equivocationPolicies = []; // [{message, mode}]
    this.committees = [];     // [{name, items:[{key,value}]}]
    this.messages = [];       // [{name, fields:[{name,ty,range}]}]
    this.cryptoObjects = [];  // [{name, kind, sourceMessage, threshold, signerRole, conflictPolicy}]
    this.pacemaker = null;    // {viewVar, startPhase, resetVars}
    this.roles = [];
    this.properties = [];     // [{name, kind, formulaText}]
  }

  static fromAST(ast) {
    const model = new VisualProtocolModel();
    const protocol = ast.protocol.node;

    model.name = protocol.name;

    // Parameters
    model.params = (protocol.parameters || []).map(p => ({
      name: p.name,
      ty: p.ty
    }));

    // Enums
    model.enums = (protocol.enums || []).map(e => ({
      name: e.name,
      variants: e.variants.slice()
    }));

    // Resilience
    if (protocol.resilience) {
      const cond = protocol.resilience.condition;
      model.resilience = linearExprToText(cond.lhs) + " " + cmpOpToText(cond.op) + " " + linearExprToText(cond.rhs);
    }

    // Pacemaker
    if (protocol.pacemaker) {
      model.pacemaker = {
        viewVar: protocol.pacemaker.view_var,
        startPhase: protocol.pacemaker.start_phase,
        resetVars: protocol.pacemaker.reset_vars.slice()
      };
    }

    // Adversary
    model.adversary = (protocol.adversary || []).map(a => ({
      key: a.key,
      value: a.value
    }));

    // Identities
    model.identities = (protocol.identities || []).map(id => ({
      role: id.role,
      scope: id.scope,
      processVar: id.process_var || null,
      key: id.key || null
    }));

    // Channels
    model.channels = (protocol.channels || []).map(ch => ({
      message: ch.message,
      auth: ch.auth
    }));

    // Equivocation
    model.equivocationPolicies = (protocol.equivocation_policies || []).map(eq => ({
      message: eq.message,
      mode: eq.mode
    }));

    // Committees
    model.committees = (protocol.committees || []).map(c => ({
      name: c.name,
      items: (c.items || []).map(item => ({
        key: item.key,
        value: committeeValueToText(item.value)
      }))
    }));

    // Messages
    model.messages = (protocol.messages || []).map(m => ({
      name: m.name,
      fields: (m.fields || []).map(f => ({
        name: f.name,
        ty: f.ty,
        range: f.range ? { min: f.range.min, max: f.range.max } : null
      }))
    }));

    // Crypto objects
    model.cryptoObjects = (protocol.crypto_objects || []).map(co => ({
      name: co.name,
      kind: co.kind,
      sourceMessage: co.source_message,
      threshold: linearExprToText(co.threshold),
      signerRole: co.signer_role || null,
      conflictPolicy: co.conflict_policy
    }));

    // Roles
    model.roles = (protocol.roles || []).map(r => {
      const role = new VisualRole(r.node.name);
      role.initPhase = r.node.init_phase || null;
      role.vars = (r.node.vars || []).map(v => ({
        name: v.name,
        ty: varTypeToText(v.ty),
        range: v.range ? { min: v.range.min, max: v.range.max } : null,
        init: v.init ? exprToText(v.init) : null
      }));
      role.phases = (r.node.phases || []).map(p => {
        const phase = new VisualPhase(p.node.name);
        phase.transitions = (p.node.transitions || []).map(t => {
          const tr = new VisualTransition();
          tr.guardText = guardToText(t.node.guard);
          tr.actions = (t.node.actions || []).map(actionFromAST);
          // Determine target phase from GotoPhase action
          const gotoAction = tr.actions.find(a => a.type === "goto");
          tr.targetPhase = gotoAction ? gotoAction.data.phase : null;
          return tr;
        });
        return phase;
      });
      return role;
    });

    // Properties
    model.properties = (protocol.properties || []).map(p => ({
      name: p.node.name,
      kind: propertyKindToText(p.node.kind),
      formulaText: quantifiedFormulaToText(p.node.formula)
    }));

    return model;
  }
}

// --- AST-to-text helpers ---

function linearExprToText(expr) {
  if (!expr) return "";
  if (typeof expr === "object") {
    if ("Const" in expr) return String(expr.Const);
    if ("Var" in expr) return expr.Var;
    if ("Add" in expr) return linearExprToText(expr.Add[0]) + " + " + linearExprToText(expr.Add[1]);
    if ("Sub" in expr) return linearExprToText(expr.Sub[0]) + " - " + linearExprToText(expr.Sub[1]);
    if ("Mul" in expr) return expr.Mul[0] + "*" + linearExprToText(expr.Mul[1]);
  }
  return String(expr);
}

function cmpOpToText(op) {
  const map = { Ge: ">=", Le: "<=", Gt: ">", Lt: "<", Eq: "==", Ne: "!=" };
  return map[op] || op || "==";
}

function exprToText(expr) {
  if (!expr) return "";
  if (typeof expr === "object") {
    if ("IntLit" in expr) return String(expr.IntLit);
    if ("BoolLit" in expr) return String(expr.BoolLit);
    if ("Var" in expr) return expr.Var;
    if ("Add" in expr) return "(" + exprToText(expr.Add[0]) + " + " + exprToText(expr.Add[1]) + ")";
    if ("Sub" in expr) return "(" + exprToText(expr.Sub[0]) + " - " + exprToText(expr.Sub[1]) + ")";
    if ("Mul" in expr) return "(" + exprToText(expr.Mul[0]) + " * " + exprToText(expr.Mul[1]) + ")";
    if ("Div" in expr) return "(" + exprToText(expr.Div[0]) + " / " + exprToText(expr.Div[1]) + ")";
    if ("Not" in expr) return "!" + exprToText(expr.Not);
    if ("Neg" in expr) return "-" + exprToText(expr.Neg);
  }
  return String(expr);
}

function varTypeToText(ty) {
  if (!ty) return "nat";
  if (typeof ty === "string") return ty.toLowerCase();
  if (typeof ty === "object") {
    if ("Enum" in ty) return ty.Enum;
    // Simple variant names
    const keys = Object.keys(ty);
    if (keys.length === 1) return keys[0].toLowerCase();
  }
  return "nat";
}

function committeeValueToText(value) {
  if (!value) return "";
  if (typeof value === "object") {
    if ("Param" in value) return value.Param;
    if ("Int" in value) return String(value.Int);
    if ("Float" in value) return String(value.Float);
  }
  return String(value);
}

function guardToText(guard) {
  if (!guard) return "";
  if (typeof guard === "object") {
    if ("Threshold" in guard) return thresholdGuardToText(guard.Threshold);
    if ("HasCryptoObject" in guard) {
      const hco = guard.HasCryptoObject;
      const argsStr = (hco.object_args || []).map(([k, v]) => k + " = " + exprToText(v)).join(", ");
      return "has " + hco.object_name + (argsStr ? "(" + argsStr + ")" : "");
    }
    if ("Comparison" in guard) {
      const c = guard.Comparison;
      return exprToText(c.lhs) + " " + cmpOpToText(c.op) + " " + exprToText(c.rhs);
    }
    if ("BoolVar" in guard) return guard.BoolVar;
    if ("And" in guard) return guardToText(guard.And[0]) + " && " + guardToText(guard.And[1]);
    if ("Or" in guard) return guardToText(guard.Or[0]) + " || " + guardToText(guard.Or[1]);
  }
  return String(guard);
}

function thresholdGuardToText(t) {
  const distinctStr = t.distinct ? "distinct " : "";
  const roleStr = t.distinct_role ? " from " + t.distinct_role : "";
  const argsStr = (t.message_args || []).map(([k, v]) => k + " = " + exprToText(v)).join(", ");
  const argsBlock = argsStr ? "(" + argsStr + ")" : "";
  return "received " + cmpOpToText(t.op) + " " + linearExprToText(t.threshold) + " " + distinctStr + t.message_type + argsBlock + roleStr;
}

function actionFromAST(action) {
  if (!action) return new VisualAction("assign", {});
  if (typeof action === "object") {
    if ("Send" in action) {
      const s = action.Send;
      return new VisualAction("send", {
        messageType: s.message_type,
        args: (s.args || []).map(sendArgToText),
        recipientRole: s.recipient_role || null
      });
    }
    if ("FormCryptoObject" in action) {
      const f = action.FormCryptoObject;
      return new VisualAction("form", {
        objectName: f.object_name,
        args: (f.args || []).map(sendArgToText),
        recipientRole: f.recipient_role || null
      });
    }
    if ("LockCryptoObject" in action) {
      const l = action.LockCryptoObject;
      return new VisualAction("lock", {
        objectName: l.object_name,
        args: (l.args || []).map(sendArgToText)
      });
    }
    if ("JustifyCryptoObject" in action) {
      const j = action.JustifyCryptoObject;
      return new VisualAction("justify", {
        objectName: j.object_name,
        args: (j.args || []).map(sendArgToText)
      });
    }
    if ("Assign" in action) {
      const a = action.Assign;
      return new VisualAction("assign", { var: a.var, value: exprToText(a.value) });
    }
    if ("GotoPhase" in action) {
      return new VisualAction("goto", { phase: action.GotoPhase.phase });
    }
    if ("Decide" in action) {
      return new VisualAction("decide", { value: exprToText(action.Decide.value) });
    }
  }
  return new VisualAction("assign", {});
}

function sendArgToText(arg) {
  if (!arg) return "";
  if ("Positional" in arg) return exprToText(arg.Positional);
  if ("Named" in arg) return arg.Named.name + ": " + exprToText(arg.Named.value);
  return String(arg);
}

function propertyKindToText(kind) {
  const map = {
    Agreement: "agreement",
    Validity: "validity",
    Safety: "safety",
    Invariant: "invariant",
    Liveness: "liveness"
  };
  return map[kind] || kind || "safety";
}

function quantifiedFormulaToText(formula) {
  if (!formula) return "";
  let text = "";
  for (const qb of formula.quantifiers || []) {
    const q = qb.quantifier === "ForAll" ? "forall" : "exists";
    text += q + " " + qb.var + ": " + qb.domain + ". ";
  }
  text += formulaExprToText(formula.body);
  return text;
}

function formulaExprToText(expr) {
  if (!expr) return "";
  if (typeof expr === "object") {
    if ("Comparison" in expr) {
      const c = expr.Comparison;
      return formulaAtomToText(c.lhs) + " " + cmpOpToText(c.op) + " " + formulaAtomToText(c.rhs);
    }
    if ("Not" in expr) return "!" + wrapBinary(expr.Not);
    if ("Next" in expr) return "X " + wrapBinary(expr.Next);
    if ("Always" in expr) return "[] " + wrapBinary(expr.Always);
    if ("Eventually" in expr) return "<> " + wrapBinary(expr.Eventually);
    if ("Until" in expr) return formulaExprToText(expr.Until[0]) + " U " + wrapBinaryRight(expr.Until[1]);
    if ("WeakUntil" in expr) return formulaExprToText(expr.WeakUntil[0]) + " W " + wrapBinaryRight(expr.WeakUntil[1]);
    if ("Release" in expr) return formulaExprToText(expr.Release[0]) + " R " + wrapBinaryRight(expr.Release[1]);
    if ("LeadsTo" in expr) return formulaExprToText(expr.LeadsTo[0]) + " ~> " + wrapBinaryRight(expr.LeadsTo[1]);
    if ("And" in expr) return formulaExprToText(expr.And[0]) + " && " + wrapBinaryRight(expr.And[1]);
    if ("Or" in expr) return formulaExprToText(expr.Or[0]) + " || " + wrapBinaryRight(expr.Or[1]);
    if ("Implies" in expr) return formulaExprToText(expr.Implies[0]) + " ==> " + wrapBinaryRight(expr.Implies[1]);
    if ("Iff" in expr) return formulaExprToText(expr.Iff[0]) + " <=> " + wrapBinaryRight(expr.Iff[1]);
  }
  return String(expr);
}

function isBinaryFormula(expr) {
  if (!expr || typeof expr !== "object") return false;
  return "And" in expr || "Or" in expr || "Implies" in expr || "Iff" in expr ||
         "Until" in expr || "WeakUntil" in expr || "Release" in expr || "LeadsTo" in expr;
}

function wrapBinary(expr) {
  if (isBinaryFormula(expr)) return "(" + formulaExprToText(expr) + ")";
  return formulaExprToText(expr);
}

function wrapBinaryRight(expr) {
  if (isBinaryFormula(expr)) return "(" + formulaExprToText(expr) + ")";
  return formulaExprToText(expr);
}

function formulaAtomToText(atom) {
  if (!atom) return "";
  if (typeof atom === "object") {
    if ("IntLit" in atom) return String(atom.IntLit);
    if ("BoolLit" in atom) return String(atom.BoolLit);
    if ("Var" in atom) return atom.Var;
    if ("QualifiedVar" in atom) return atom.QualifiedVar.object + "." + atom.QualifiedVar.field;
  }
  return String(atom);
}
