from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from typer.testing import CliRunner

from coordinator.chainattest_coordinator.ops import app
from coordinator.chainattest_coordinator.service import CoordinatorService


class OperatorCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="chainattest-ops-"))
        self.db_path = self.temp_dir / "chainattest.db"
        self.state_path = self.temp_dir / "jobs.json"
        self.audit_log_path = self.temp_dir / "audit.jsonl"
        self.runner = CliRunner()
        self.service = CoordinatorService(
            state_path=self.state_path,
            audit_log_path=self.audit_log_path,
            db_path=self.db_path,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir)

    def _invoke(self, *args: str) -> object:
        result = self.runner.invoke(app, list(args))
        self.assertEqual(result.exit_code, 0, msg=result.stdout)
        return json.loads(result.stdout)

    def test_list_jobs_and_show_job_report_persisted_state(self) -> None:
        input_path = self.temp_dir / "input.json"
        input_path.write_text("{}\n")

        job = self.service.submit_job("ops-check", input_path)
        self.service.start_job(job.job_id)

        listed = self._invoke(
            "list-jobs",
            "--db-path",
            str(self.db_path),
        )
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["job_id"], job.job_id)

        shown = self._invoke(
            "show-job",
            job.job_id,
            "--db-path",
            str(self.db_path),
        )
        self.assertEqual(shown["job_id"], job.job_id)
        self.assertEqual(shown["state"], "running")

    def test_tail_audit_returns_recent_records(self) -> None:
        input_path = self.temp_dir / "input.json"
        input_path.write_text("{}\n")

        job = self.service.submit_job("audit-check", input_path)
        self.service.start_job(job.job_id)
        self.service.complete_job(job.job_id)

        records = self._invoke(
            "tail-audit",
            "--db-path",
            str(self.db_path),
            "--limit",
            "2",
        )
        self.assertEqual(len(records), 2)
        self.assertEqual(records[-1]["event_type"], "job_completed")


if __name__ == "__main__":
    unittest.main()
