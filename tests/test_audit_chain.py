import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import Request, urlopen

from src.domain import Actor, PermissionDenied
from src.http_api import create_server
from src.repository import GENESIS_HASH, SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService


def make_service(path):
    repo = SQLiteRepository(path)
    return DomainService(repo, RuleEngine())


def create_dataset(service, name="Chain Dataset", actor=None):
    return service.create(
        actor or Actor("admin", "admin"),
        "dataset",
        {"name": name, "access_policy": "controlled"},
    )


class AuditChainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "test.db"
        self.service = make_service(self.db_path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_chain_is_intact_after_normal_writes(self):
        create_dataset(self.service)
        entity = create_dataset(self.service, name="Second")
        self.service.transition(
            Actor("admin", "admin"), entity["id"], "restrict", {"reason": "review"}
        )
        report = self.service.repository.verify_audit()
        self.assertTrue(report["intact"])
        self.assertEqual(report["count"], 3)
        self.assertEqual(report["stored_count"], 3)
        self.assertIsNone(report["first_bad_seq"])

        items = self.service.audit_log()
        self.assertEqual([item["seq"] for item in items], [1, 2, 3])
        self.assertEqual(items[0]["prev_hash"], GENESIS_HASH)
        self.assertTrue(all(len(item["hash"]) == 64 for item in items))

    def test_modifying_a_record_breaks_at_that_seq(self):
        first = create_dataset(self.service)
        create_dataset(self.service, "Second")
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE audit_log SET action = ? WHERE entity_id = ?",
                ("tampered", first["id"]),
            )
        report = self.service.repository.verify_audit()
        self.assertFalse(report["intact"])
        self.assertEqual(report["first_bad_seq"], 1)

    def test_deleting_middle_record_breaks_at_missing_seq(self):
        create_dataset(self.service)
        second = create_dataset(self.service, "Second")
        create_dataset(self.service, "Third")
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("DELETE FROM audit_log WHERE entity_id = ?", (second["id"],))
        report = self.service.repository.verify_audit()
        self.assertFalse(report["intact"])
        self.assertEqual(report["first_bad_seq"], 2)

    def test_deleting_tail_record_is_exposed_by_chain_counter(self):
        create_dataset(self.service)
        second = create_dataset(self.service, "Second")
        with sqlite3.connect(self.db_path) as raw:
            # Attacker removes the last record but the independently stored
            # chain tail/counter still claims two records.
            raw.execute("DELETE FROM audit_log WHERE entity_id = ?", (second["id"],))
        report = self.service.repository.verify_audit()
        self.assertFalse(report["intact"])
        self.assertEqual(report["first_bad_seq"], 2)

    def test_reordering_records_breaks_chain(self):
        first = create_dataset(self.service)
        second = create_dataset(self.service, "Second")
        with sqlite3.connect(self.db_path) as raw:
            # Swap the payloads of the two positions: stored hashes no longer
            # line up in chain order.
            raw.execute(
                "UPDATE audit_log SET entity_id = ? WHERE seq = 1", (second["id"],)
            )
            raw.execute(
                "UPDATE audit_log SET entity_id = ? WHERE seq = 2", (first["id"],)
            )
        report = self.service.repository.verify_audit()
        self.assertFalse(report["intact"])
        self.assertEqual(report["first_bad_seq"], 1)

    def test_concurrent_writes_form_a_single_chain(self):
        errors = []

        def worker(index):
            try:
                create_dataset(self.service, name="Concurrent %d" % index)
            except Exception as exc:  # pragma: no cover - surfaces concurrency failures
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        report = self.service.repository.verify_audit()
        self.assertTrue(report["intact"], report)
        self.assertEqual(report["count"], 20)
        seqs = {item["seq"] for item in self.service.audit_log()}
        self.assertEqual(seqs, set(range(1, 21)))

    def test_legacy_records_without_hashes_are_backfilled_then_chained(self):
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "INSERT INTO audit_log("
                "entity_id, actor_id, actor_role, action, from_status, to_status, "
                "detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("legacy-1", "admin", "admin", "create", None, "registered",
                 json.dumps({"kind": "dataset"}, sort_keys=True), "2026-01-01T00:00:00+00:00"),
            )
            raw.execute(
                "INSERT INTO audit_log("
                "entity_id, actor_id, actor_role, action, from_status, to_status, "
                "detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("legacy-2", "admin", "admin", "restrict", "registered", "restricted",
                 json.dumps({"reason": "x"}, sort_keys=True), "2026-01-02T00:00:00+00:00"),
            )
            raw.execute("UPDATE audit_chain SET count = 0, tail_hash = ? WHERE id = 1",
                        (GENESIS_HASH,))

        restarted = make_service(self.db_path)
        report = restarted.repository.verify_audit()
        self.assertTrue(report["intact"], report)
        self.assertEqual(report["count"], 2)
        create_dataset(restarted, "After Backfill")
        report = restarted.repository.verify_audit()
        self.assertTrue(report["intact"], report)
        self.assertEqual(report["count"], 3)
        items = restarted.audit_log()
        self.assertEqual([item["seq"] for item in items], [1, 2, 3])

    def test_only_admin_and_auditor_can_verify(self):
        create_dataset(self.service)
        self.assertTrue(self.service.verify_audit(Actor("boss", "admin"))["intact"])
        self.assertTrue(self.service.verify_audit(Actor("review", "auditor"))["intact"])
        with self.assertRaises(PermissionDenied):
            self.service.verify_audit(Actor("user", "applicant"))
        # The regular audit query is unchanged and stays open.
        self.assertEqual(len(self.service.audit_log()), 1)


class AuditVerifyHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.service = DomainService(repo, RuleEngine())
        create_dataset(self.service)
        static_dir = str(Path(__file__).resolve().parent.parent / "static")
        self.server = create_server("127.0.0.1", 0, self.service, RuleEngine(), static_dir)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        self.tmp.cleanup()

    def _verify(self, role):
        request = Request(
            "http://127.0.0.1:%d/api/audit/verify" % self.port,
            headers={"X-User-Id": "tester", "X-Role": role},
        )
        return urlopen(request, timeout=5)

    def test_verify_endpoint_for_auditor(self):
        with self._verify("auditor") as response:
            payload = json.loads(response.read().decode("utf-8"))
        self.assertTrue(payload["intact"])
        self.assertEqual(payload["count"], 1)

    def test_verify_endpoint_denied_for_viewer(self):
        from urllib.error import HTTPError

        with self.assertRaises(HTTPError) as caught:
            self._verify("viewer")
        self.assertEqual(caught.exception.code, 403)


if __name__ == "__main__":
    unittest.main()
