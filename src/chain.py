import hashlib
import json

CHAIN_VERSION = "audit-chain-v1"
GENESIS_HASH = ""


def compute_digest(
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
    """根据本条记录内容与上一条摘要计算指纹。

    detail_text 必须是入库时的原始 JSON 文本，保证补算与写入一致。
    """
    canonical = json.dumps(
        [
            CHAIN_VERSION,
            int(seq),
            prev_hash or GENESIS_HASH,
            entity_id,
            actor_id,
            actor_role,
            action,
            from_status,
            to_status,
            detail_text,
            created_at,
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
