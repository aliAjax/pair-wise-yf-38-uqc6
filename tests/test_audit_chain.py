import json
import sqlite3
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

from src.domain import Actor, PermissionDenied
from src.http_api import create_server
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService


CHAIN_FIELDS = (
    "entity_id",
    "actor_id",
    "actor_role",
    "action",
    "from_status",
    "to_status",
    "detail",
    "created_at",
)


class AuditChainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "test.db"
        self.repo = SQLiteRepository(self.db_path)
        self.service = DomainService(self.repo, RuleEngine())
        self.actor = Actor("admin", "admin")

    def tearDown(self):
        self.tmp.cleanup()

    def _seed(self, count=3):
        ids = []
        for index in range(count):
            entity = self.service.create(
                self.actor,
                "dataset",
                {"name": "D-%s" % index, "access_policy": "controlled"},
            )
            ids.append(entity["id"])
        return ids

    def _raw(self):
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def test_intact_chain(self):
        self._seed(3)
        report = self.repo.verify_chain()
        self.assertTrue(report["intact"])
        self.assertEqual(report["record_count"], 3)
        self.assertEqual(report["tail_count"], 3)
        self.assertIsNone(report["first_broken_seq"])

        rows = self.repo.list_audit()
        self.assertEqual([item["id"] for item in rows], [1, 2, 3])
        # 原有查询不暴露链字段
        self.assertNotIn("hash", rows[0])
        self.assertNotIn("seq", rows[0])

    def test_modified_record_breaks_at_its_seq(self):
        self._seed(3)
        with self._raw() as connection:
            connection.execute(
                "UPDATE audit_log SET action = ? WHERE seq = 2", ("tampered",)
            )
        report = self.repo.verify_chain()
        self.assertFalse(report["intact"])
        self.assertEqual(report["first_broken_seq"], 2)

    def test_modified_detail_breaks(self):
        self._seed(2)
        with self._raw() as connection:
            connection.execute(
                "UPDATE audit_log SET detail = ? WHERE seq = 1",
                (json.dumps({"kind": "grant"}),),
            )
        report = self.repo.verify_chain()
        self.assertFalse(report["intact"])
        self.assertEqual(report["first_broken_seq"], 1)

    def test_deleted_middle_record_breaks_at_gap(self):
        self._seed(4)
        with self._raw() as connection:
            connection.execute("DELETE FROM audit_log WHERE seq = 2")
        report = self.repo.verify_chain()
        self.assertFalse(report["intact"])
        self.assertEqual(report["record_count"], 3)
        self.assertEqual(report["tail_count"], 4)
        self.assertEqual(report["first_broken_seq"], 2)

    def test_deleted_last_record_found_by_tail_count(self):
        self._seed(3)
        with self._raw() as connection:
            connection.execute("DELETE FROM audit_log WHERE seq = 3")
        report = self.repo.verify_chain()
        self.assertFalse(report["intact"])
        self.assertEqual(report["record_count"], 2)
        self.assertEqual(report["tail_count"], 3)
        self.assertEqual(report["first_broken_seq"], 3)

    def test_reordered_records_break(self):
        self._seed(3)
        with self._raw() as connection:
            first = connection.execute(
                "SELECT * FROM audit_log WHERE seq = 1"
            ).fetchone()
            second = connection.execute(
                "SELECT * FROM audit_log WHERE seq = 2"
            ).fetchone()
            # 对调两条记录的载荷，保留各自的 seq/指纹：签名立刻对不上
            assignments = ", ".join(field + " = ?" for field in CHAIN_FIELDS)
            params_two = [second[field] for field in CHAIN_FIELDS] + [1]
            params_one = [first[field] for field in CHAIN_FIELDS] + [2]
            connection.execute(
                "UPDATE audit_log SET " + assignments + " WHERE seq = ?",
                params_two,
            )
            connection.execute(
                "UPDATE audit_log SET " + assignments + " WHERE seq = ?",
                params_one,
            )
        report = self.repo.verify_chain()
        self.assertFalse(report["intact"])
        self.assertEqual(report["first_broken_seq"], 1)

    def test_recomputed_chain_without_tail_still_broken(self):
        self._seed(3)
        # 攻击者重排内容并重算了全部指纹，却未更新链尾：链尾摘要对不上
        from src.chain import GENESIS_HASH, compute_digest

        with self._raw() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_log ORDER BY seq"
            ).fetchall()
            payloads = [dict(row) for row in rows]
            payloads[0]["entity_id"], payloads[1]["entity_id"] = (
                payloads[1]["entity_id"],
                payloads[0]["entity_id"],
            )
            prev_hash = GENESIS_HASH
            for pos, payload in enumerate(payloads, start=1):
                digest = compute_digest(
                    seq=pos,
                    prev_hash=prev_hash,
                    entity_id=payload["entity_id"],
                    actor_id=payload["actor_id"],
                    actor_role=payload["actor_role"],
                    action=payload["action"],
                    from_status=payload["from_status"],
                    to_status=payload["to_status"],
                    detail_text=payload["detail"],
                    created_at=payload["created_at"],
                )
                connection.execute(
                    "UPDATE audit_log SET entity_id = ?, prev_hash = ?, hash = ? WHERE seq = ?",
                    (payload["entity_id"], prev_hash, digest, pos),
                )
                prev_hash = digest
        report = self.repo.verify_chain()
        self.assertFalse(report["intact"])
        self.assertEqual(report["first_broken_seq"], 3)

    def test_old_records_backfilled_in_id_order(self):
        # 丢弃新结构库，模拟只有旧 audit_log 的历史数据库
        self.repo = None
        Path(self.db_path).unlink()
        legacy = sqlite3.connect(self.db_path)
        legacy.executescript("""
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                actor_role TEXT NOT NULL,
                action TEXT NOT NULL,
                from_status TEXT,
                to_status TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """)
        for index in range(3):
            legacy.execute(
                "INSERT INTO audit_log(entity_id, actor_id, actor_role, action, "
                "from_status, to_status, detail, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "ent-%s" % index,
                    "admin",
                    "admin",
                    "create",
                    None,
                    "registered",
                    json.dumps({"kind": "dataset"}, sort_keys=True),
                    "2026-09-2%sT00:00:00+00:00" % index,
                ),
            )
        legacy.commit()
        legacy.close()

        repo = SQLiteRepository(self.db_path)  # 触发迁移与补算
        self.repo = repo
        report = repo.verify_chain()
        self.assertTrue(report["intact"])
        self.assertEqual(report["record_count"], 3)
        self.assertEqual(report["tail_count"], 3)

        # 补算之后再写新账，必须接在补好的链尾之后
        self.service.create(
            self.actor,
            "dataset",
            {"name": "new", "access_policy": "controlled"},
        )
        report = self.repo.verify_chain()
        self.assertTrue(report["intact"])
        self.assertEqual(report["record_count"], 4)

    def test_concurrent_appends_form_single_chain(self):
        def worker():
            barrier.wait()
            self.repo.append_audit(
                "ent", "actor", "admin", "ping", None, "registered", {}
            )

        threads_count = 20
        barrier = threading.Barrier(threads_count)
        threads = [threading.Thread(target=worker) for _ in range(threads_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        with self._raw() as connection:
            seqs = [
                row[0]
                for row in connection.execute(
                    "SELECT seq FROM audit_log ORDER BY seq"
                ).fetchall()
            ]
        self.assertEqual(seqs, list(range(1, threads_count + 1)))
        report = self.repo.verify_chain()
        self.assertTrue(report["intact"])
        self.assertEqual(report["record_count"], threads_count)
        self.assertEqual(report["tail_count"], threads_count)

    def test_verify_permission(self):
        self._seed(1)
        self.assertTrue(self.service.verify_audit(Actor("a", "auditor"))["intact"])
        self.assertTrue(self.service.verify_audit(Actor("a", "admin"))["intact"])
        with self.assertRaises(PermissionDenied):
            self.service.verify_audit(Actor("a", "viewer"))


class AuditVerifyHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.service = DomainService(repo, RuleEngine())
        self.service.create(
            Actor("admin", "admin"),
            "dataset",
            {"name": "D", "access_policy": "controlled"},
        )
        static_dir = Path(__file__).resolve().parent.parent / "static"
        self.server = create_server("127.0.0.1", 0, self.service, RuleEngine(), str(static_dir))
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.tmp.cleanup()

    def _get(self, path, role):
        request = urllib.request.Request(
            "http://127.0.0.1:%s%s" % (self.port, path),
            headers={"X-User-Id": "u", "X-Role": role},
        )
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_verify_endpoint_access(self):
        status, payload = self._get("/api/audit/verify", "admin")
        self.assertEqual(status, 200)
        self.assertTrue(payload["intact"])
        self.assertEqual(payload["record_count"], 1)

        status, _ = self._get("/api/audit/verify", "auditor")
        self.assertEqual(status, 200)

        status, payload = self._get("/api/audit/verify", "viewer")
        self.assertEqual(status, 403)
        self.assertEqual(payload["type"], "PermissionDenied")

    def test_audit_query_unchanged(self):
        status, payload = self._get("/api/audit", "viewer")
        self.assertEqual(status, 200)
        self.assertEqual(len(payload["items"]), 1)
        self.assertNotIn("hash", payload["items"][0])


if __name__ == "__main__":
    unittest.main()
