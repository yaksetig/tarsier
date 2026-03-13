import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


REPO_ROOT = Path(__file__).resolve().parents[1]
CHECKER_SCRIPT = REPO_ROOT / ".github" / "scripts" / "check_checker_soundness_artifact.py"
CRYPTO_SCRIPT = REPO_ROOT / ".github" / "scripts" / "check_crypto_semantics_contract.py"


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load module {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_file(root: Path, relpath: str, contents: str) -> Path:
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")
    return path


class ContractScriptTests(unittest.TestCase):
    def test_checker_soundness_artifact_accepts_tests_in_secondary_source_file(self) -> None:
        module = load_module("check_checker_soundness_artifact_test", CHECKER_SCRIPT)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            doc = write_file(
                root,
                "docs/CHECKER_SOUNDNESS_ARGUMENT.md",
                """## Soundness Claim
## Machine-Checked Subset Proof
## Assumptions (Explicit + Test-Linked)
## Explicit Non-Goals (Boundary + Test-Linked)
## CI Enforcement
soundness_subset_profile_validator_matches_reference_spec
soundness_subset_bundle_hash_matches_spec_vectors
certcheck_passes_valid_bundle_with_mock_solver
certcheck_fails_on_tampered_obligation
check_checker_soundness_artifact.py
Checker Soundness Subset Gate
""",
            )
            lib_rs = write_file(root, "crates/tarsier-proof-kernel/src/lib.rs", "// empty")
            tests_rs = write_file(
                root,
                "crates/tarsier-proof-kernel/src/tests.rs",
                """#[test]
fn soundness_subset_profile_validator_matches_reference_spec() {}

#[test]
fn soundness_subset_bundle_hash_matches_spec_vectors() {}
""",
            )
            certcheck = write_file(
                root,
                "crates/tarsier-certcheck/tests/integration.rs",
                """#[test]
fn certcheck_passes_valid_bundle_with_mock_solver() {}

#[test]
fn certcheck_fails_on_tampered_obligation() {}
""",
            )

            errors = module.check_checker_soundness_artifact(
                doc,
                [lib_rs, tests_rs],
                certcheck,
                root,
            )

            self.assertEqual(errors, [])

    def test_checker_soundness_artifact_reports_missing_kernel_test(self) -> None:
        module = load_module("check_checker_soundness_artifact_missing", CHECKER_SCRIPT)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            doc = write_file(
                root,
                "docs/CHECKER_SOUNDNESS_ARGUMENT.md",
                """## Soundness Claim
## Machine-Checked Subset Proof
## Assumptions (Explicit + Test-Linked)
## Explicit Non-Goals (Boundary + Test-Linked)
## CI Enforcement
soundness_subset_profile_validator_matches_reference_spec
soundness_subset_bundle_hash_matches_spec_vectors
certcheck_passes_valid_bundle_with_mock_solver
certcheck_fails_on_tampered_obligation
check_checker_soundness_artifact.py
Checker Soundness Subset Gate
""",
            )
            lib_rs = write_file(root, "crates/tarsier-proof-kernel/src/lib.rs", "// empty")
            tests_rs = write_file(
                root,
                "crates/tarsier-proof-kernel/src/tests.rs",
                """#[test]
fn soundness_subset_profile_validator_matches_reference_spec() {}
""",
            )
            certcheck = write_file(
                root,
                "crates/tarsier-certcheck/tests/integration.rs",
                """#[test]
fn certcheck_passes_valid_bundle_with_mock_solver() {}

#[test]
fn certcheck_fails_on_tampered_obligation() {}
""",
            )

            errors = module.check_checker_soundness_artifact(
                doc,
                [lib_rs, tests_rs],
                certcheck,
                root,
            )

            self.assertIn(
                "crates/tarsier-proof-kernel/src: missing test function `soundness_subset_bundle_hash_matches_spec_vectors`",
                errors,
            )

    def test_crypto_semantics_contract_accepts_encoder_tests_in_tests_rs(self) -> None:
        module = load_module("check_crypto_semantics_contract_test", CRYPTO_SCRIPT)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            doc = write_file(
                root,
                "docs/SEMANTICS.md",
                """## 2.5 Crypto Object Operational Semantics
### `form C(...)`
### `lock C(...)`
### `justify C(...)`
### `certificate` vs `threshold_signature`
### IR and SMT Mapping (Test-Linked)
lower_crypto_object_form_lock_justify
lower_threshold_signature_form_filters_witnesses_to_signer_role
lower_rejects_threshold_signature_without_signer_role
lower_lock_adds_implicit_has_threshold_guard
lower_justify_sets_justify_flag_not_lock_flag
lower_crypto_object_conflicts_exclusive_adds_admissibility_guard
forging_crypto_object_family_is_unsat_even_with_byzantine_budget
valid_crypto_object_formation_path_is_sat
exclusive_crypto_policy_blocks_conflicting_variants_in_same_state
crypto_justify_independent_of_lock
""",
            )
            lowering = write_file(
                root,
                "crates/tarsier-ir/src/lowering/tests.rs",
                """#[test]
fn lower_crypto_object_form_lock_justify() {}
#[test]
fn lower_threshold_signature_form_filters_witnesses_to_signer_role() {}
#[test]
fn lower_rejects_threshold_signature_without_signer_role() {}
#[test]
fn lower_lock_adds_implicit_has_threshold_guard() {}
#[test]
fn lower_justify_sets_justify_flag_not_lock_flag() {}
#[test]
fn lower_crypto_object_conflicts_exclusive_adds_admissibility_guard() {}
""",
            )
            encoder_mod = write_file(root, "crates/tarsier-smt/src/encoder/mod.rs", "// empty")
            encoder_tests = write_file(
                root,
                "crates/tarsier-smt/src/encoder/tests.rs",
                """#[test]
fn forging_crypto_object_family_is_unsat_even_with_byzantine_budget() {}
#[test]
fn valid_crypto_object_formation_path_is_sat() {}
#[test]
fn exclusive_crypto_policy_blocks_conflicting_variants_in_same_state() {}
""",
            )
            engine_integration = write_file(
                root,
                "crates/tarsier-engine/tests/faithful_tests.rs",
                """#[test]
fn crypto_justify_independent_of_lock() {}
""",
            )

            errors = module.check_crypto_semantics_contract(
                doc,
                lowering,
                [encoder_mod, encoder_tests],
                engine_integration,
                root,
            )

            self.assertEqual(errors, [])

    def test_crypto_semantics_contract_reports_missing_encoder_test(self) -> None:
        module = load_module("check_crypto_semantics_contract_missing", CRYPTO_SCRIPT)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            doc = write_file(
                root,
                "docs/SEMANTICS.md",
                """## 2.5 Crypto Object Operational Semantics
### `form C(...)`
### `lock C(...)`
### `justify C(...)`
### `certificate` vs `threshold_signature`
### IR and SMT Mapping (Test-Linked)
lower_crypto_object_form_lock_justify
lower_threshold_signature_form_filters_witnesses_to_signer_role
lower_rejects_threshold_signature_without_signer_role
lower_lock_adds_implicit_has_threshold_guard
lower_justify_sets_justify_flag_not_lock_flag
lower_crypto_object_conflicts_exclusive_adds_admissibility_guard
forging_crypto_object_family_is_unsat_even_with_byzantine_budget
valid_crypto_object_formation_path_is_sat
exclusive_crypto_policy_blocks_conflicting_variants_in_same_state
crypto_justify_independent_of_lock
""",
            )
            lowering = write_file(
                root,
                "crates/tarsier-ir/src/lowering/tests.rs",
                """#[test]
fn lower_crypto_object_form_lock_justify() {}
#[test]
fn lower_threshold_signature_form_filters_witnesses_to_signer_role() {}
#[test]
fn lower_rejects_threshold_signature_without_signer_role() {}
#[test]
fn lower_lock_adds_implicit_has_threshold_guard() {}
#[test]
fn lower_justify_sets_justify_flag_not_lock_flag() {}
#[test]
fn lower_crypto_object_conflicts_exclusive_adds_admissibility_guard() {}
""",
            )
            encoder_mod = write_file(root, "crates/tarsier-smt/src/encoder/mod.rs", "// empty")
            encoder_tests = write_file(
                root,
                "crates/tarsier-smt/src/encoder/tests.rs",
                """#[test]
fn forging_crypto_object_family_is_unsat_even_with_byzantine_budget() {}
#[test]
fn valid_crypto_object_formation_path_is_sat() {}
""",
            )
            engine_integration = write_file(
                root,
                "crates/tarsier-engine/tests/faithful_tests.rs",
                """#[test]
fn crypto_justify_independent_of_lock() {}
""",
            )

            errors = module.check_crypto_semantics_contract(
                doc,
                lowering,
                [encoder_mod, encoder_tests],
                engine_integration,
                root,
            )

            self.assertIn(
                "crates/tarsier-smt/src/encoder: missing test function `exclusive_crypto_policy_blocks_conflicting_variants_in_same_state`",
                errors,
            )


if __name__ == "__main__":
    unittest.main()
