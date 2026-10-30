import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, call, patch

from click.testing import CliRunner
from pyartcd.cli import cli
from pyartcd.pipelines.verify_advisory_transition import (
    ADVISORY_TRANSITION_FAIL_LABEL as FAIL,
)
from pyartcd.pipelines.verify_advisory_transition import (
    ADVISORY_TRANSITION_PENDING_LABEL as PENDING,
)
from pyartcd.pipelines.verify_advisory_transition import (
    ADVISORY_TRANSITION_SUCCESS_LABEL as SUCCESS,
)
from pyartcd.pipelines.verify_advisory_transition import (
    VerifyAdvisoryTransitionPipeline,
)

from pyartcd import jenkins

MODULE = "pyartcd.pipelines.verify_advisory_transition"
MR_URL = "https://gitlab.cee.redhat.com/hybrid-platforms/art/ocp-shipment-data/-/merge_requests/42"


class AdvisoryTransitionTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp_dir = self.enterContext(tempfile.TemporaryDirectory())
        self.runtime = MagicMock(dry_run=False, working_dir=Path(self.temp_dir))
        self.pipeline = VerifyAdvisoryTransitionPipeline(self.runtime, "4.22", "4.22.9", 42)
        self.load_config = self.enterContext(patch(f"{MODULE}.util.load_group_config", new_callable=AsyncMock))
        self.load_config.return_value = {"shipment": {"url": MR_URL}}
        self.gitlab = self.enterContext(patch(f"{MODULE}.GitLabClient.from_url")).return_value
        self.mr = self.gitlab.get_mr_from_url.return_value
        self.mr.labels = ["verify-release-success", "unrelated", PENDING]
        self.command = self.enterContext(patch(f"{MODULE}.exectools.cmd_assert_async", new_callable=AsyncMock))
        self.inspect = self.enterContext(patch(f"{MODULE}.exectools.cmd_gather_async", new_callable=AsyncMock))
        self.advisories = [{"advisory_id": 100, "status": "QE"}, {"advisory_id": 101, "status": "QE"}]
        self.inspect.return_value = (1, json.dumps({"advisories": self.advisories}), "")
        self.gitlab.add_mr_labels.side_effect = self.update_labels

    def update_labels(self, url, labels, remove_labels=None):
        self.assertEqual(url, MR_URL)
        self.mr.labels = list((set(self.mr.labels) | set(labels)) - set(remove_labels or []))

    def assert_failed(self):
        self.assertIn(FAIL, self.mr.labels)
        self.assertNotIn(PENDING, self.mr.labels)
        self.assertNotIn(SUCCESS, self.mr.labels)
        self.assertIn("unrelated", self.mr.labels)
        self.gitlab.add_mr_labels.assert_called_with(MR_URL, [FAIL], remove_labels=[PENDING])


class TestVerifyAdvisoryTransition(AdvisoryTransitionTestCase):
    async def test_success_only_after_final_verification(self):
        async def command(cmd):
            self.assertNotIn(SUCCESS, self.mr.labels)
            self.assertIn(PENDING, self.mr.labels)

        self.command.side_effect = command
        await self.pipeline.run()
        commands = [entry.args[0] for entry in self.command.call_args_list]
        self.assertEqual(commands[0][-1], "verify-metadata-url")
        self.assertEqual(
            [cmd[-7:] for cmd in commands[1:-1]],
            [
                ["change-state", "-s", "REL_PREP", "--from", "QE", "--advisory", str(advisory)]
                for advisory in (100, 101)
            ],
        )
        self.assertEqual(commands[-1][-1], "verify-advisory-status")
        self.assertNotIn("--mark", commands[-1])
        self.gitlab.add_mr_labels.assert_has_calls(
            [call(MR_URL, [PENDING]), call(MR_URL, [SUCCESS], remove_labels=[PENDING])]
        )
        self.assertIn(SUCCESS, self.mr.labels)
        self.assertNotIn(PENDING, self.mr.labels)

    async def test_early_config_failure_labels_origin(self):
        self.load_config.side_effect = RuntimeError("configuration unavailable")
        with self.assertRaisesRegex(RuntimeError, "configuration unavailable"):
            await self.pipeline.run()
        self.assert_failed()
        self.command.assert_not_called()
        self.gitlab.get_mr_from_url.assert_called_with(MR_URL)

    async def test_missing_shipment_and_origin_mismatch_fail_before_commands(self):
        for config in ({}, {"shipment": {"url": MR_URL + "9"}}):
            with self.subTest(config=config):
                self.mr.labels = ["verify-release-success", "unrelated", PENDING]
                self.load_config.return_value = config
                with self.assertRaises(ValueError):
                    await self.pipeline.run()
                self.assert_failed()
                self.command.assert_not_called()

    async def test_all_command_failures_are_terminal(self):
        for outcomes in (
            [ChildProcessError("metadata")],
            [None, ChildProcessError("Errata unavailable")],
            [None, None, ChildProcessError("partial transition")],
            [None, None, None, ChildProcessError("final verification")],
        ):
            with self.subTest(outcomes=outcomes):
                self.mr.labels = ["verify-release-success", "unrelated", PENDING]
                self.command.side_effect = outcomes
                with self.assertRaises(ChildProcessError):
                    await self.pipeline.run()
                self.assert_failed()
                self.command.reset_mock(side_effect=True)
                await self.pipeline.run()
                self.command.assert_not_called()

    async def test_failed_attempt_can_retry_only_after_manual_label_removal(self):
        self.mr.labels.append(FAIL)
        await self.pipeline.run()
        self.load_config.assert_not_called()
        self.mr.labels.remove(FAIL)
        await self.pipeline.run()
        self.assertIn(SUCCESS, self.mr.labels)

    async def test_closed_and_merged_origin_mrs_are_processed(self):
        for state in ("closed", "merged"):
            with self.subTest(state=state):
                self.mr.state = state
                self.mr.labels = ["verify-release-success", "unrelated", PENDING]
                self.command.reset_mock()
                await self.pipeline.run()
                self.assertIn(SUCCESS, self.mr.labels)
                self.assertNotIn(PENDING, self.mr.labels)
                self.assertEqual(self.command.await_count, 4)

    async def test_new_files_is_not_transitioned_and_final_rejection_is_terminal(self):
        self.inspect.return_value = (1, json.dumps({"advisories": [{"advisory_id": 100, "status": "NEW_FILES"}]}), "")
        self.command.side_effect = [None, ChildProcessError("NEW_FILES remains")]
        with self.assertRaisesRegex(ChildProcessError, "NEW_FILES remains"):
            await self.pipeline.run()
        commands = [entry.args[0] for entry in self.command.call_args_list]
        self.assertEqual([cmd[-1] for cmd in commands], ["verify-metadata-url", "verify-advisory-status"])
        self.assert_failed()

    async def test_origin_lookup_failure_keeps_pending_without_commands_or_labels(self):
        self.gitlab.get_mr_from_url.side_effect = RuntimeError("GitLab unavailable")
        with self.assertRaisesRegex(RuntimeError, "GitLab unavailable"):
            await self.pipeline.run()
        self.assertIn(PENDING, self.mr.labels)
        self.command.assert_not_called()
        self.load_config.assert_not_called()
        self.gitlab.add_mr_labels.assert_not_called()

    async def test_terminal_labels_skip_even_before_loading_config(self):
        for label in (SUCCESS, FAIL):
            self.mr.labels = ["verify-release-success", label]
            await self.pipeline.run()
        self.load_config.assert_not_called()
        self.gitlab.add_mr_labels.assert_not_called()


class TestAdvisoryTransitionCLI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.config = self.temp_dir / "artcd.toml"
        self.config.write_text("")
        self.runner = CliRunner()
        self.options = [
            "--config",
            str(self.config),
            "--working-dir",
            str(self.temp_dir),
            "verify-advisory-transition",
            "--version",
            "4.22",
            "--assembly",
            "4.22.9",
        ]

    def test_requires_positive_integer_origin_before_service_access(self):
        with patch(f"{MODULE}.GitLabClient.from_url") as gitlab:
            for value in (None, "0", "-1", "1; echo unexpected", "1.5"):
                with self.subTest(value=value):
                    options = self.options + ([] if value is None else ["--shipment-mr-iid", value])
                    result = self.runner.invoke(cli, options)
                    self.assertEqual(result.exit_code, 2, result.output)
                    self.assertIn("shipment-mr-iid", result.output)
            gitlab.assert_not_called()

    def test_helper_parameters_reach_actual_cli_pipeline_and_origin(self):
        with patch("pyartcd.jenkins.start_build") as start_build:
            jenkins.start_verify_advisory_transition("4.22", "4.22.9", 42, block_until_building=False)
        params = start_build.call_args.kwargs["params"]
        self.assertEqual(params, {"BUILD_VERSION": "4.22", "ASSEMBLY": "4.22.9", "SHIPMENT_MR_IID": 42})
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            with (
                patch(f"{MODULE}.GitLabClient.from_url") as gitlab,
                patch(f"{MODULE}.util.load_group_config", new_callable=AsyncMock) as config,
                patch(f"{MODULE}.exectools.cmd_assert_async", new_callable=AsyncMock) as command,
                patch(f"{MODULE}.exectools.cmd_gather_async", new_callable=AsyncMock) as inspect,
            ):
                gitlab.return_value.get_mr_from_url.return_value.labels = ["verify-release-success", PENDING]
                config.return_value = {"shipment": {"url": MR_URL}}
                inspect.return_value = (0, '{"advisories": [{"advisory_id": 100, "status": "REL_PREP"}]}', "")
                options = self.options[:4] + [
                    "verify-advisory-transition",
                    f"--version={params['BUILD_VERSION']}",
                    f"--assembly={params['ASSEMBLY']}",
                    f"--shipment-mr-iid={params['SHIPMENT_MR_IID']}",
                ]
                result = self.runner.invoke(cli, options)
                self.assertEqual(result.exit_code, 0, result.output or str(result.exception))
                gitlab.assert_called_once_with(MR_URL, dry_run=False)
                gitlab.return_value.add_mr_labels.assert_called_with(MR_URL, [SUCCESS], remove_labels=[PENDING])
                self.assertEqual(command.await_count, 2)
        finally:
            loop.close()
            asyncio.set_event_loop(None)


class TestAdvisoryTransitionFailures(AdvisoryTransitionTestCase):
    async def test_unverified_origin_is_terminal(self):
        self.mr.labels.remove("verify-release-success")
        with self.assertRaisesRegex(ValueError, "verify-release-success"):
            await self.pipeline.run()
        self.assert_failed()

    async def test_inspection_errors_and_invalid_states_are_terminal(self):
        for inspection in (
            (2, "", "service unavailable"),
            (1, "not json", ""),
            (1, '{"advisories": []}', ""),
            (1, '{"advisories": [{"advisory_id": -1, "status": "QE"}]}', ""),
            (1, '{"advisories": [{"advisory_id": 100, "error": "API failed"}]}', ""),
        ):
            with self.subTest(inspection=inspection):
                self.mr.labels = ["verify-release-success", "unrelated", PENDING]
                self.inspect.return_value = inspection
                with self.assertRaises((ValueError, RuntimeError)):
                    await self.pipeline.run()
                self.assert_failed()

    async def test_later_states_are_not_transitioned(self):
        for state in ("REL_PREP", "PUSH_READY", "IN_PUSH", "SHIPPED_LIVE", "DROPPED_NO_SHIP"):
            self.mr.labels = ["verify-release-success", PENDING]
            self.inspect.return_value = (0, json.dumps({"advisories": [{"advisory_id": 100, "status": state}]}), "")
            self.command.reset_mock()
            await self.pipeline.run()
            self.assertEqual(self.command.await_count, 2)

    async def test_failed_terminal_persistence_preserves_reservation_and_original_error(self):
        self.gitlab.add_mr_labels.side_effect = [None, RuntimeError("GitLab unavailable")]
        self.command.side_effect = ChildProcessError("original error")
        with self.assertLogs(MODULE, level="ERROR"), self.assertRaisesRegex(ChildProcessError, "original error"):
            await self.pipeline.run()
        self.assertIn(PENDING, self.mr.labels)
        self.assertNotIn(SUCCESS, self.mr.labels)

    async def test_success_persistence_failure_retains_reservation_without_marking_fail(self):
        self.gitlab.add_mr_labels.side_effect = [None, RuntimeError("GitLab unavailable")]
        with self.assertRaisesRegex(RuntimeError, "GitLab unavailable"):
            await self.pipeline.run()
        self.assertIn(PENDING, self.mr.labels)
        self.assertNotIn(FAIL, self.mr.labels)
        self.assertNotIn(SUCCESS, self.mr.labels)

    async def test_failure_marking_never_overwrites_existing_success(self):
        async def command(cmd):
            self.mr.labels.append(SUCCESS)
            raise ChildProcessError("original")

        self.command.side_effect = command
        with self.assertRaises(ChildProcessError):
            await self.pipeline.run()
        self.assertNotIn(FAIL, self.mr.labels)

    async def test_dry_run_never_changes_labels(self):
        self.runtime.dry_run = True
        labels = self.mr.labels.copy()
        await self.pipeline.run()
        for entry in self.command.call_args_list[1:]:
            self.assertEqual(entry.args[0][-1], "--dry-run")
        self.assertEqual(self.mr.labels, labels)
        self.gitlab.add_mr_labels.assert_not_called()
        self.load_config.side_effect = RuntimeError("configuration unavailable")
        with self.assertRaises(RuntimeError):
            await self.pipeline.run()
        self.gitlab.add_mr_labels.assert_not_called()
