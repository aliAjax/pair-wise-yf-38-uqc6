import json
import sqlite3
from datetime import datetime, timezone

from .chain import GENESIS_HASH, compute_digest
from .domain import ConflictError, NotFoundError


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class SQLiteRepository:
    def __init__(self, path):
        self.path = str(path)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self):
        with self._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS entities (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    data TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_entities_kind_status
                    ON entities(kind, status);
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    actor_role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    from_status TEXT,
                    to_status TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    seq INTEGER,
                    prev_hash TEXT,
                    hash TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_audit_entity
                    ON audit_log(entity_id, id);
                CREATE TABLE IF NOT EXISTS audit_chain (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    tail_seq INTEGER NOT NULL,
                    tail_hash TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS idempotency (
                    actor_id TEXT NOT NULL,
                    idem_key TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(actor_id, idem_key)
                );
            """)
            self._migrate_audit_chain(connection)

    def _migrate_audit_chain(self, connection):
        """旧库补链：若存在未计算指纹的记录，按 id 顺序补算后接续。"""
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(audit_log)").fetchall()
        }
        if "seq" not in columns:
            connection.execute("ALTER TABLE audit_log ADD COLUMN seq INTEGER")
        if "prev_hash" not in columns:
            connection.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT")
        if "hash" not in columns:
            connection.execute("ALTER TABLE audit_log ADD COLUMN hash TEXT")
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_seq ON audit_log(seq)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS audit_chain ("
            "id INTEGER PRIMARY KEY CHECK (id = 1), "
            "tail_seq INTEGER NOT NULL, tail_hash TEXT NOT NULL, "
            "updated_at TEXT NOT NULL)"
        )

        state = connection.execute(
            "SELECT tail_seq, tail_hash FROM audit_chain WHERE id = 1"
        ).fetchone()
        rows = connection.execute(
            "SELECT id, entity_id, actor_id, actor_role, action, from_status, "
            "to_status, detail, created_at, seq, prev_hash, hash "
            "FROM audit_log ORDER BY id"
        ).fetchall()
        pending = [row for row in rows if row["seq"] is None or row["hash"] is None]
        if not pending and state:
            return

        if state:
            # 链尾已存在：只补未入链的新记录
            tail_seq = int(state["tail_seq"])
            tail_hash = state["tail_hash"]
        else:
            # 链从未建立：旧记录按 id 顺序全部补算
            tail_seq = 0
            tail_hash = GENESIS_HASH
            for row in rows:
                seq = tail_seq + 1
                digest = self._row_digest(row, seq, tail_hash)
                connection.execute(
                    "UPDATE audit_log SET seq = ?, prev_hash = ?, hash = ? WHERE id = ?",
                    (seq, tail_hash, digest, row["id"]),
                )
                tail_seq = seq
                tail_hash = digest
            pending = []
        for row in pending:
            seq = tail_seq + 1
            digest = self._row_digest(row, seq, tail_hash)
            connection.execute(
                "UPDATE audit_log SET seq = ?, prev_hash = ?, hash = ? WHERE id = ?",
                (seq, tail_hash, digest, row["id"]),
            )
            tail_seq = seq
            tail_hash = digest
        if tail_seq:
            connection.execute(
                "INSERT OR REPLACE INTO audit_chain(id, tail_seq, tail_hash, updated_at) "
                "VALUES (1, ?, ?, ?)",
                (tail_seq, tail_hash, utcnow()),
            )

    @staticmethod
    def _row_digest(row, seq, prev_hash):
        return compute_digest(
            seq=seq,
            prev_hash=prev_hash,
            entity_id=row["entity_id"],
            actor_id=row["actor_id"],
            actor_role=row["actor_role"],
            action=row["action"],
            from_status=row["from_status"],
            to_status=row["to_status"],
            detail_text=row["detail"],
            created_at=row["created_at"],
        )

    @staticmethod
    def _entity_from_row(row):
        return {
            "id": row["id"],
            "kind": row["kind"],
            "status": row["status"],
            "version": int(row["version"]),
            "data": json.loads(row["data"]),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def create_entity(self, entity_id, kind, status, data, actor_id):
        now = utcnow()
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO entities(id, kind, status, version, data, created_by, created_at, updated_at) "
                "VALUES (?, ?, ?, 1, ?, ?, ?, ?)",
                (entity_id, kind, status, payload, actor_id, now, now),
            )
        return self.get_entity(entity_id)

    def get_entity(self, entity_id):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM entities WHERE id = ?", (entity_id,)
            ).fetchone()
        return self._entity_from_row(row) if row else None

    def list_entities(self, kind=None, status=None):
        clauses = []
        params = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM entities" + where + " ORDER BY created_at, id", params
            ).fetchall()
        return [self._entity_from_row(row) for row in rows]

    def find_entities(self, kind, field, value):
        return [
            entity
            for entity in self.list_entities(kind=kind)
            if (entity["id"] == value if field == "id" else entity["data"].get(field) == value)
        ]

    def update_entity(self, entity_id, expected_version, status, data):
        now = utcnow()
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT version FROM entities WHERE id = ?", (entity_id,)
            ).fetchone()
            if not row:
                raise NotFoundError("entity not found: " + entity_id)
            current_version = int(row["version"])
            if expected_version is not None and current_version != int(expected_version):
                raise ConflictError(
                    "version conflict: expected %s, found %s"
                    % (expected_version, current_version)
                )
            connection.execute(
                "UPDATE entities SET status = ?, version = version + 1, data = ?, updated_at = ? "
                "WHERE id = ? AND version = ?",
                (status, payload, now, entity_id, current_version),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get_entity(entity_id)

    def append_audit(self, entity_id, actor_id, actor_role, action, from_status, to_status, detail):
        detail_text = json.dumps(detail, ensure_ascii=False, sort_keys=True)
        created_at = utcnow()
        connection = self._connect()
        try:
            # 立即取得保留锁：两个并发写账在此串行，只能排成单链
            connection.execute("BEGIN IMMEDIATE")
            state = connection.execute(
                "SELECT tail_seq, tail_hash FROM audit_chain WHERE id = 1"
            ).fetchone()
            if state:
                seq = int(state["tail_seq"]) + 1
                prev_hash = state["tail_hash"]
            else:
                seq = 1
                prev_hash = GENESIS_HASH
            digest = compute_digest(
                seq=seq,
                prev_hash=prev_hash,
                entity_id=entity_id,
                actor_id=actor_id,
                actor_role=actor_role,
                action=action,
                from_status=from_status,
                to_status=to_status,
                detail_text=detail_text,
                created_at=created_at,
            )
            connection.execute(
                "INSERT INTO audit_log(entity_id, actor_id, actor_role, action, "
                "from_status, to_status, detail, created_at, seq, prev_hash, hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entity_id,
                    actor_id,
                    actor_role,
                    action,
                    from_status,
                    to_status,
                    detail_text,
                    created_at,
                    seq,
                    prev_hash,
                    digest,
                ),
            )
            connection.execute(
                "INSERT INTO audit_chain(id, tail_seq, tail_hash, updated_at) "
                "VALUES (1, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET "
                "tail_seq = excluded.tail_seq, tail_hash = excluded.tail_hash, "
                "updated_at = excluded.updated_at",
                (seq, digest, created_at),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def verify_chain(self):
        """重放整条审计指纹链，返回完好状态、记录数与首个断点。"""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id, entity_id, actor_id, actor_role, action, from_status, "
                "to_status, detail, created_at, seq, prev_hash, hash "
                "FROM audit_log ORDER BY seq"
            ).fetchall()
            state = connection.execute(
                "SELECT tail_seq, tail_hash FROM audit_chain WHERE id = 1"
            ).fetchone()

        count = len(rows)
        first_broken_seq = None
        expected_seq = 1
        prev_hash = GENESIS_HASH
        last_id = 0
        tail_hash = GENESIS_HASH

        for row in rows:
            stored_seq = row["seq"]
            if stored_seq is None or int(stored_seq) != expected_seq:
                broken = True  # 调序或序号断档（含中间删除）
            elif row["id"] <= last_id:
                broken = True  # id 不单调：物理行被对调
            elif row["prev_hash"] != prev_hash:
                broken = True  # 与上一条接不上
            elif row["hash"] != self._row_digest(row, expected_seq, prev_hash):
                broken = True  # 内容被改动
            else:
                broken = False
            if broken and first_broken_seq is None:
                first_broken_seq = expected_seq

            # 无论是否异常都按存储值推进，继续定位首个断点
            if stored_seq is not None:
                expected_seq = int(stored_seq) + 1
            last_id = max(last_id, row["id"])
            current_hash = row["hash"] or GENESIS_HASH
            tail_hash = current_hash
            prev_hash = current_hash

        if state is None:
            if count:
                if first_broken_seq is None:
                    first_broken_seq = 1
                tail_count = 0
                stored_tail_hash = GENESIS_HASH
            else:
                tail_count = 0
                stored_tail_hash = GENESIS_HASH
        else:
            tail_count = int(state["tail_seq"])
            stored_tail_hash = state["tail_hash"]

        if first_broken_seq is None and count != tail_count:
            # 链尾少一条（或多出未入链的记录）
            first_broken_seq = min(count, tail_count) + 1
        if first_broken_seq is None and stored_tail_hash != tail_hash:
            first_broken_seq = tail_count

        return {
            "intact": first_broken_seq is None and count == tail_count,
            "record_count": count,
            "tail_count": tail_count,
            "first_broken_seq": first_broken_seq,
            "tail_hash": stored_tail_hash if state else GENESIS_HASH,
        }

    def list_audit(self, entity_id=None):
        with self._connect() as connection:
            if entity_id:
                rows = connection.execute(
                    "SELECT * FROM audit_log WHERE entity_id = ? ORDER BY id", (entity_id,)
                ).fetchall()
            else:
                rows = connection.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        return [
            {
                "id": row["id"],
                "entity_id": row["entity_id"],
                "actor_id": row["actor_id"],
                "actor_role": row["actor_role"],
                "action": row["action"],
                "from_status": row["from_status"],
                "to_status": row["to_status"],
                "detail": json.loads(row["detail"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def get_idempotency(self, actor_id, idem_key):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT entity_id FROM idempotency WHERE actor_id = ? AND idem_key = ?",
                (actor_id, idem_key),
            ).fetchone()
        return row["entity_id"] if row else None

    def save_idempotency(self, actor_id, idem_key, entity_id):
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO idempotency(actor_id, idem_key, entity_id, created_at) "
                "VALUES (?, ?, ?, ?)",
                (actor_id, idem_key, entity_id, utcnow()),
            )

    def ping(self):
        with self._connect() as connection:
            connection.execute("SELECT 1").fetchone()
        return True
