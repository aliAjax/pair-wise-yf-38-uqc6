import hashlib
import json
import sqlite3
from datetime import datetime, timezone

from .domain import ConflictError, NotFoundError


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


GENESIS_HASH = "0" * 64


def _fingerprint(
    seq,
    prev_hash,
    entity_id,
    actor_id,
    actor_role,
    action,
    from_status,
    to_status,
    detail_text,
    created_at,
):
    material = [
        int(seq),
        prev_hash,
        entity_id,
        actor_id,
        actor_role,
        action,
        from_status,
        to_status,
        detail_text,
        created_at,
    ]
    encoded = json.dumps(
        material, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def canonical_detail(detail):
    return json.dumps(detail or {}, ensure_ascii=False, sort_keys=True)


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
                CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_seq
                    ON audit_log(seq)
                    WHERE seq IS NOT NULL;
                CREATE TABLE IF NOT EXISTS audit_chain (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    tail_hash TEXT NOT NULL,
                    count INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS idempotency (
                    actor_id TEXT NOT NULL,
                    idem_key TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(actor_id, idem_key)
                );
            """)
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
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_seq "
                "ON audit_log(seq) WHERE seq IS NOT NULL"
            )
            connection.execute(
                "INSERT OR IGNORE INTO audit_chain(id, tail_hash, count) "
                "VALUES (1, ?, 0)",
                (GENESIS_HASH,),
            )
            self._backfill_chain(connection)

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

    @staticmethod
    def _backfill_chain(connection):
        row = connection.execute(
            "SELECT tail_hash, count FROM audit_chain WHERE id = 1"
        ).fetchone()
        prev_hash = row["tail_hash"] if row else GENESIS_HASH
        expected = row["count"] if row else 0
        rows = connection.execute(
            "SELECT * FROM audit_log WHERE seq IS NULL ORDER BY id"
        ).fetchall()
        if not rows:
            return
        for row_entry in rows:
            seq = expected + 1
            digest = _fingerprint(
                seq,
                prev_hash,
                row_entry["entity_id"],
                row_entry["actor_id"],
                row_entry["actor_role"],
                row_entry["action"],
                row_entry["from_status"],
                row_entry["to_status"],
                row_entry["detail"],
                row_entry["created_at"],
            )
            connection.execute(
                "UPDATE audit_log SET seq = ?, prev_hash = ?, hash = ? WHERE id = ?",
                (seq, prev_hash, digest, row_entry["id"]),
            )
            prev_hash = digest
            expected = seq
        connection.execute(
            "UPDATE audit_chain SET tail_hash = ?, count = ? WHERE id = 1",
            (prev_hash, expected),
        )

    def append_audit(self, entity_id, actor_id, actor_role, action, from_status, to_status, detail):
        detail_text = canonical_detail(detail)
        created_at = utcnow()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            # Defensive: records inserted outside the chain are chained first.
            self._backfill_chain(connection)
            tail = connection.execute(
                "SELECT tail_hash, count FROM audit_chain WHERE id = 1"
            ).fetchone()
            if tail is None:
                tail_hash, count = GENESIS_HASH, 0
                connection.execute(
                    "INSERT INTO audit_chain(id, tail_hash, count) VALUES (1, ?, 0)",
                    (GENESIS_HASH,),
                )
            else:
                tail_hash, count = tail["tail_hash"], int(tail["count"])
            seq = count + 1
            digest = _fingerprint(
                seq,
                tail_hash,
                entity_id,
                actor_id,
                actor_role,
                action,
                from_status,
                to_status,
                detail_text,
                created_at,
            )
            connection.execute(
                "INSERT INTO audit_log("
                "entity_id, actor_id, actor_role, action, from_status, to_status, "
                "detail, created_at, seq, prev_hash, hash) "
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
                    tail_hash,
                    digest,
                ),
            )
            connection.execute(
                "UPDATE audit_chain SET tail_hash = ?, count = ? WHERE id = 1",
                (digest, seq),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def verify_audit(self):
        with self._connect() as connection:
            chain = connection.execute(
                "SELECT tail_hash, count FROM audit_chain WHERE id = 1"
            ).fetchone()
            tail_hash = chain["tail_hash"] if chain else GENESIS_HASH
            chain_count = int(chain["count"]) if chain else 0
            rows = connection.execute(
                "SELECT * FROM audit_log ORDER BY seq, id"
            ).fetchall()

        stored_count = len(rows)
        prev_hash = GENESIS_HASH
        expected_seq = 0
        first_bad_seq = None
        for row in rows:
            expected_seq += 1
            stored_seq = None if row["seq"] is None else int(row["seq"])
            digest = _fingerprint(
                expected_seq,
                prev_hash,
                row["entity_id"],
                row["actor_id"],
                row["actor_role"],
                row["action"],
                row["from_status"],
                row["to_status"],
                row["detail"],
                row["created_at"],
            )
            if (
                stored_seq != expected_seq
                or row["prev_hash"] != prev_hash
                or row["hash"] != digest
            ):
                first_bad_seq = expected_seq
                break
            prev_hash = digest

        if first_bad_seq is None:
            if stored_count < chain_count:
                # Records removed from the tail: the chain counter exposes the gap.
                first_bad_seq = chain_count
            elif stored_count > chain_count:
                first_bad_seq = chain_count + 1
            elif prev_hash != tail_hash:
                first_bad_seq = chain_count if chain_count else 1

        return {
            "intact": first_bad_seq is None,
            "count": chain_count,
            "stored_count": stored_count,
            "first_bad_seq": first_bad_seq,
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
                "seq": row["seq"],
                "prev_hash": row["prev_hash"],
                "hash": row["hash"],
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
