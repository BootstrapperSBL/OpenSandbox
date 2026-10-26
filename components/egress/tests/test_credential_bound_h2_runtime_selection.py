# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0

"""Pure case-selection and denominator checks for the opt-in runtime runner."""

import unittest

import test_credential_bound_h2_runtime as runner


def initial_cases(overrides=None):
    overrides = overrides or {}
    return [
        {"case": name, "status": overrides.get(name, "NOT_RUN")}
        for name in [*runner.CASES, *runner.GO_CASES]
    ]


class RuntimeSelectionTests(unittest.TestCase):
    def test_no_go_client_keeps_existing_runtime_denominator(self):
        self.assertEqual(runner.select_cases(None, False), runner.CASES)

    def test_go_client_default_selects_candidate_cases_only(self):
        selected = runner.select_cases(None, True)
        self.assertEqual(selected, [*runner.CASES, *runner.GO_EARLY_CASES])
        self.assertTrue(set(runner.GO_EARLY_CASES).issubset(selected))
        self.assertFalse(set(runner.GO_DELAYED_CASES).intersection(selected))

    def test_historical_diagnostic_failure_does_not_contaminate_default_gate(self):
        selected = runner.select_cases(None, True)
        statuses = {name: "PASS" for name in selected}
        statuses.update({name: "FAIL" for name in runner.GO_DELAYED_CASES})
        summary = runner.summarize_results(initial_cases(statuses), selected)

        self.assertEqual(summary["status"], "PASS")
        self.assertEqual(
            summary["denominator_summaries"]["candidate_acceptance"]["status"],
            "PASS",
        )
        self.assertEqual(
            summary["denominator_summaries"][
                "go_delayed_held_old_diagnostic_not_candidate_gate"
            ]["status"],
            "FAIL",
        )
        self.assertEqual(
            summary["denominator_summaries"][
                "go_bounded_old_diagnostic_not_candidate_gate"
            ]["status"],
            "FAIL",
        )

    def test_explicit_historical_diagnostic_retains_its_own_failure(self):
        selected = runner.select_cases(["go_retry"], True)
        summary = runner.summarize_results(
            initial_cases({"go_retry": "FAIL"}), selected
        )

        self.assertEqual(summary["status"], "FAIL")
        self.assertEqual(
            summary["denominator_summaries"]["candidate_acceptance"]["status"],
            "NOT_RUN",
        )
        self.assertEqual(
            summary["denominator_summaries"][
                "go_delayed_held_old_diagnostic_not_candidate_gate"
            ]["status"],
            "FAIL",
        )

    def test_sparse_candidate_results_leave_missing_rows_not_run(self):
        selected = [*runner.REAL_RUNTIME_CASES, *runner.GO_EARLY_CASES]
        summary = runner.summarize_results(
            [{"case": runner.REAL_RUNTIME_CASES[0], "status": "PASS"}],
            selected,
        )

        candidate = summary["denominator_summaries"]["candidate_acceptance"]
        self.assertEqual("NOT_RUN", summary["status"])
        self.assertEqual("NOT_RUN", candidate["status"])
        self.assertEqual(3, candidate["denominator"])
        self.assertEqual(
            {"PASS": 1, "FAIL": 0, "BLOCKED": 0, "NOT_RUN": 2},
            candidate["counts"],
        )
        self.assertEqual(
            {"PASS": 1, "FAIL": 0, "BLOCKED": 0, "NOT_RUN": 19},
            summary["summary"],
        )
        self.assertEqual(20, sum(summary["summary"].values()))
        for group in summary["denominator_summaries"].values():
            self.assertEqual(group["denominator"], sum(group["counts"].values()))

    def test_duplicate_cases_and_unknown_statuses_are_rejected(self):
        name = runner.REAL_RUNTIME_CASES[0]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            runner.summarize_results(
                [{"case": name, "status": "PASS"},
                 {"case": name, "status": "NOT_RUN"}],
                [name],
            )
        with self.assertRaisesRegex(ValueError, "status"):
            runner.summarize_results([{"case": name, "status": "SKIPPED"}], [name])
        with self.assertRaisesRegex(ValueError, "unknown selected case"):
            runner.summarize_results([], ["unknown-case"])

    def test_early_notice_failure_keeps_candidate_gate_nonzero(self):
        selected = runner.select_cases(None, True)
        statuses = {name: "PASS" for name in selected}
        statuses["go_early_notice_h2_origin"] = "FAIL"
        summary = runner.summarize_results(initial_cases(statuses), selected)

        self.assertEqual(summary["status"], "FAIL")
        self.assertEqual(
            summary["denominator_summaries"]["candidate_acceptance"]["status"],
            "FAIL",
        )
        self.assertEqual(runner.exit_code_for_status(summary["status"]), 1)


if __name__ == "__main__":
    unittest.main()
