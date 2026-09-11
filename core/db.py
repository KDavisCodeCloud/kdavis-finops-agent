"""Shared asyncpg connection setup.

asyncpg has no built-in jsonb/json decoding: without a codec registered,
every jsonb column comes back as a raw JSON string instead of a parsed
dict/list, and INSERTs of native dict/list values fail. Same fix as
kdavis-agentic-platform/core/db.py (proven necessary there against the
same class of Postgres pooler) -- pass this as create_pool's init=.
"""

import json


async def register_jsonb_codec(conn) -> None:
    await conn.set_type_codec(
        "jsonb",
        encoder=json.dumps,
        decoder=json.loads,
        schema="pg_catalog",
    )
    await conn.set_type_codec(
        "json",
        encoder=json.dumps,
        decoder=json.loads,
        schema="pg_catalog",
    )
