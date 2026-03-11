/-
  Tarsier Proof Kernel — Formal Semantics (KERN-03)

  This module encodes the checker semantics from the exported
  kernel_semantics_v1.json artifact and proves a minimal soundness
  theorem: if `check_bundle` returns no issues, then all integrity
  predicates hold for the bundle.

  Scope (matching KERNEL_FORMALIZATION_RFC.md §2):
  - Profile admissibility
  - Obligation completeness
  - Path safety
  - Hash consistency
  - SMT structural sanity
  - Bundle hash integrity

  Trust assumptions (out of scope):
  - Solver correctness
  - SMT formula correctness w.r.t. protocol semantics
  - Filesystem / OS primitives
  - Hash function collision resistance
-/

-- ============================================================
-- 1. Domain types (mirroring kernel_semantics_v1.json)
-- ============================================================

/-- Certificate kinds supported by the kernel. -/
inductive CertKind where
  | safety_proof
  | fair_liveness_proof
  deriving DecidableEq, Repr

/-- Proof engines supported by the kernel. -/
inductive ProofEngine where
  | kinduction
  | pdr
  deriving DecidableEq, Repr

/-- Fairness annotations for liveness certificates. -/
inductive Fairness where
  | weak
  | strong
  deriving DecidableEq, Repr

/-- Expected solver result for an obligation. -/
inductive Expected where
  | unsat
  | sat
  | unknown
  deriving DecidableEq, Repr

/-- An obligation within a certificate bundle. -/
structure Obligation where
  name : String
  expected : Expected
  file : String
  sha256 : Option String
  proof_file : Option String
  proof_sha256 : Option String
  deriving Repr

/-- Certificate metadata (mirrors CertificateMetadata in lib.rs). -/
structure CertificateMetadata where
  schema_version : Nat
  kind : CertKind
  protocol_file : String
  proof_engine : ProofEngine
  induction_k : Option Nat
  solver_used : String
  soundness : String
  fairness : Option Fairness
  bundle_sha256 : Option String
  obligations : List Obligation
  deriving Repr

-- ============================================================
-- 2. Filesystem and hash abstractions (trusted axioms)
-- ============================================================

/-- Abstract hash function: bytes → hex digest.
    We do not model SHA-256 internals. -/
opaque Hash : Type := String

/-- Abstract filesystem oracle: resolves paths to file contents. -/
structure FileSystem where
  /-- Read file contents, if it exists. -/
  read_file : String → Option (List UInt8)
  /-- Canonical resolution of a path. -/
  canonicalize : String → String
  /-- The bundle root directory (canonical). -/
  bundle_root : String

/-- Compute hash of bytes (abstract). -/
axiom hash_bytes : List UInt8 → String

/-- Compute bundle hash from metadata fields (abstract, mirrors
    `compute_bundle_sha256` in lib.rs). -/
axiom compute_bundle_hash : CertificateMetadata → String

-- ============================================================
-- 3. Predicates (integrity properties)
-- ============================================================

/-- The required schema version. -/
def CERTIFICATE_SCHEMA_VERSION : Nat := 2

/-- Profile admissibility: the (kind, engine, fairness) triple is valid. -/
def profile_admissible (m : CertificateMetadata) : Prop :=
  match m.kind, m.proof_engine with
  | .safety_proof, .kinduction => m.fairness = none
  | .safety_proof, .pdr => m.fairness = none
  | .fair_liveness_proof, .pdr =>
      m.fairness = some .weak ∨ m.fairness = some .strong
  | .fair_liveness_proof, .kinduction => False

/-- Required obligation names for a given profile. -/
def required_obligations (kind : CertKind) (engine : ProofEngine) : List String :=
  match kind, engine with
  | .safety_proof, .kinduction => ["base_case", "inductive_step"]
  | .safety_proof, .pdr =>
      ["init_implies_inv", "inv_and_transition_implies_inv_prime", "inv_implies_safe"]
  | .fair_liveness_proof, .pdr =>
      ["init_implies_inv", "inv_and_transition_implies_inv_prime", "inv_implies_no_fair_bad"]
  | .fair_liveness_proof, .kinduction => []  -- invalid profile

/-- Obligation completeness: all required obligations are present. -/
def obligation_complete (m : CertificateMetadata) : Prop :=
  ∀ name ∈ required_obligations m.kind m.proof_engine,
    ∃ o ∈ m.obligations, o.name = name

/-- No unexpected obligation names. -/
def no_unexpected_obligations (m : CertificateMetadata) : Prop :=
  ∀ o ∈ m.obligations,
    o.name ∈ required_obligations m.kind m.proof_engine

/-- Path safety: no traversal components (abstract predicate).
    The full check in Rust examines path components; here we axiomatize it. -/
axiom is_safe_path : String → Prop

/-- All obligation file paths are safe. -/
def all_paths_safe (m : CertificateMetadata) : Prop :=
  ∀ o ∈ m.obligations, is_safe_path o.file ∧
    match o.proof_file with
    | some pf => is_safe_path pf
    | none => True

/-- All proof obligations expect unsat (required for proof certificates). -/
def all_obligations_unsat (m : CertificateMetadata) : Prop :=
  ∀ o ∈ m.obligations, o.expected = .unsat

/-- Hash consistency for a single obligation (abstract). -/
def obligation_hash_consistent (fs : FileSystem) (bundle_dir : String) (o : Obligation) : Prop :=
  match o.sha256 with
  | some expected_hash =>
      match fs.read_file (bundle_dir ++ "/" ++ o.file) with
      | some contents => hash_bytes contents = expected_hash
      | none => False  -- file must exist
  | none => False  -- hash must be present

/-- All obligation hashes are consistent. -/
def all_hashes_consistent (fs : FileSystem) (bundle_dir : String) (m : CertificateMetadata) : Prop :=
  ∀ o ∈ m.obligations, obligation_hash_consistent fs bundle_dir o

/-- Bundle hash matches computed value. -/
def bundle_hash_valid (m : CertificateMetadata) : Prop :=
  match m.bundle_sha256 with
  | some h => compute_bundle_hash m = h
  | none => False

/-- SMT structural sanity for obligation content (abstract predicate). -/
def smt_structurally_valid (_content : List UInt8) : Prop :=
  True  -- Abstracted: kernel checks check-sat count, exit count, command order, assert presence

/-- Induction parameter is present when required. -/
def induction_k_present (m : CertificateMetadata) : Prop :=
  m.induction_k.isSome

/-- Non-empty obligations list. -/
def obligations_nonempty (m : CertificateMetadata) : Prop :=
  m.obligations ≠ []

/-- No duplicate obligation names. -/
def no_duplicate_names (m : CertificateMetadata) : Prop :=
  ∀ (i j : Fin m.obligations.length), i ≠ j →
    (m.obligations.get i).name ≠ (m.obligations.get j).name

-- ============================================================
-- 4. Combined integrity predicate
-- ============================================================

/-- All integrity predicates that the kernel enforces. -/
def integrity_predicates_hold (fs : FileSystem) (bundle_dir : String) (m : CertificateMetadata) : Prop :=
  m.schema_version = CERTIFICATE_SCHEMA_VERSION ∧
  profile_admissible m ∧
  obligation_complete m ∧
  no_unexpected_obligations m ∧
  all_paths_safe m ∧
  all_obligations_unsat m ∧
  all_hashes_consistent fs bundle_dir m ∧
  bundle_hash_valid m ∧
  induction_k_present m ∧
  obligations_nonempty m ∧
  no_duplicate_names m

-- ============================================================
-- 5. Issue codes (mirroring kernel_semantics_v1.json)
-- ============================================================

/-- Issue codes emitted by the kernel checker. -/
inductive IssueCode where
  | bundle_hash_mismatch
  | check_sat_count
  | disallowed_commands
  | duplicate_obligation_file
  | duplicate_obligation_name
  | empty_obligations
  | exit_count
  | invalid_command_order
  | invalid_expected
  | invalid_expected_for_proof
  | invalid_kind
  | invalid_obligation_extension
  | invalid_proof_engine
  | missing_assert
  | missing_bundle_hash
  | missing_file
  | missing_induction_k
  | missing_obligation_hash
  | missing_or_invalid_fairness
  | missing_proof_file
  | missing_proof_hash
  | missing_required_obligation
  | obligation_hash_mismatch
  | orphan_proof_hash
  | proof_hash_mismatch
  | schema_version
  | symlink_escape
  | unexpected_fairness
  | unexpected_obligation_name
  | unsafe_path
  | unsafe_proof_path
  deriving DecidableEq, Repr

/-- A single check issue with code and message. -/
structure CheckIssue where
  code : IssueCode
  message : String

/-- The integrity report returned by the checker. -/
structure IntegrityReport where
  metadata : CertificateMetadata
  issues : List CheckIssue

/-- A report is OK when no issues are present. -/
def IntegrityReport.is_ok (r : IntegrityReport) : Prop :=
  r.issues = []

-- ============================================================
-- 6. Abstract checker model
-- ============================================================

/-- The checker function (abstract model of check_bundle_integrity).
    We axiomatize its core property rather than re-implementing the
    full Rust logic: it is a function that, given a filesystem and
    bundle directory, produces an integrity report. -/
axiom check_bundle : FileSystem → String → CertificateMetadata → IntegrityReport

/-- **Checker contract axiom**: The checker emits no issues only when
    all integrity predicates hold. This is the statement that the Rust
    implementation must satisfy, and is the target for formal
    verification against the Rust source in future work.

    For this prototype, we axiomatize this correspondence and prove
    the soundness theorem from it. -/
axiom checker_contract :
  ∀ (fs : FileSystem) (bundle_dir : String) (m : CertificateMetadata),
    (check_bundle fs bundle_dir m).is_ok →
    integrity_predicates_hold fs bundle_dir m

-- ============================================================
-- 7. Soundness theorem
-- ============================================================

/-- **Minimal soundness theorem (KERN-03 target)**:
    If the kernel checker accepts a bundle (returns is_ok), then all
    integrity predicates hold for that bundle.

    This is a direct consequence of the checker contract axiom. The
    value of this formalization is:
    1. It precisely defines what "integrity_predicates_hold" means.
    2. It enumerates every predicate the checker must enforce.
    3. It provides a framework for future refinement where the axiom
       is replaced by a verified implementation proof. -/
theorem kernel_soundness
    (fs : FileSystem) (bundle_dir : String) (m : CertificateMetadata)
    (h : (check_bundle fs bundle_dir m).is_ok) :
    integrity_predicates_hold fs bundle_dir m :=
  checker_contract fs bundle_dir m h

-- ============================================================
-- 8. Decomposition lemmas (useful for downstream consumers)
-- ============================================================

theorem kernel_accepts_implies_schema_valid
    (fs : FileSystem) (bundle_dir : String) (m : CertificateMetadata)
    (h : (check_bundle fs bundle_dir m).is_ok) :
    m.schema_version = CERTIFICATE_SCHEMA_VERSION :=
  (kernel_soundness fs bundle_dir m h).1

theorem kernel_accepts_implies_profile_admissible
    (fs : FileSystem) (bundle_dir : String) (m : CertificateMetadata)
    (h : (check_bundle fs bundle_dir m).is_ok) :
    profile_admissible m :=
  (kernel_soundness fs bundle_dir m h).2.1

theorem kernel_accepts_implies_obligations_complete
    (fs : FileSystem) (bundle_dir : String) (m : CertificateMetadata)
    (h : (check_bundle fs bundle_dir m).is_ok) :
    obligation_complete m :=
  (kernel_soundness fs bundle_dir m h).2.2.1

theorem kernel_accepts_implies_paths_safe
    (fs : FileSystem) (bundle_dir : String) (m : CertificateMetadata)
    (h : (check_bundle fs bundle_dir m).is_ok) :
    all_paths_safe m :=
  (kernel_soundness fs bundle_dir m h).2.2.2.2.1

theorem kernel_accepts_implies_hashes_consistent
    (fs : FileSystem) (bundle_dir : String) (m : CertificateMetadata)
    (h : (check_bundle fs bundle_dir m).is_ok) :
    all_hashes_consistent fs bundle_dir m :=
  (kernel_soundness fs bundle_dir m h).2.2.2.2.2.2.1

theorem kernel_accepts_implies_bundle_hash_valid
    (fs : FileSystem) (bundle_dir : String) (m : CertificateMetadata)
    (h : (check_bundle fs bundle_dir m).is_ok) :
    bundle_hash_valid m :=
  (kernel_soundness fs bundle_dir m h).2.2.2.2.2.2.2.1

-- ============================================================
-- 9. Negative example: rejected bundle
-- ============================================================

/-- Construct a bundle that violates schema version. -/
def bad_schema_bundle : CertificateMetadata :=
  { schema_version := 99
    kind := .safety_proof
    protocol_file := "test.trs"
    proof_engine := .kinduction
    induction_k := some 4
    solver_used := "z3"
    soundness := "strict"
    fairness := none
    bundle_sha256 := none
    obligations := [] }

/-- The bad-schema bundle cannot satisfy integrity predicates
    (schema_version ≠ 2). -/
theorem bad_schema_not_accepted :
    ¬ (bad_schema_bundle.schema_version = CERTIFICATE_SCHEMA_VERSION) := by
  simp [bad_schema_bundle, CERTIFICATE_SCHEMA_VERSION]

/-- A fair_liveness_proof with kinduction engine is not profile-admissible. -/
def bad_profile_bundle : CertificateMetadata :=
  { schema_version := 2
    kind := .fair_liveness_proof
    protocol_file := "test.trs"
    proof_engine := .kinduction
    induction_k := some 4
    solver_used := "z3"
    soundness := "strict"
    fairness := some .weak
    bundle_sha256 := none
    obligations := [] }

theorem bad_profile_not_admissible :
    ¬ profile_admissible bad_profile_bundle := by
  simp [profile_admissible, bad_profile_bundle]
