"""
Database Module — Server-Side SQLite Storage (Enhanced)
=======================================================

Tables:
  • encrypted_files  — file metadata (UUID, filename, timestamp)
  • encrypted_index  — token → file mapping with token type & relevance
  • file_counter     — monotonic counter for forward privacy
  • search_history   — anonymized search analytics

Token types:
  K = exact keyword, N = n-gram substring, B = bigram phrase
"""

import sqlite3
import os

DB_PATH = os.environ.get("SSE_DB_PATH", "sse_server_local.db")


def _get_connection(db_path: str = None) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path or DB_PATH)
    # WAL/DELETE can fail on some drives/filesystems; MEMORY is the safest fallback.
    journal_mode = os.environ.get("SSE_SQLITE_JOURNAL_MODE", "MEMORY").upper()
    if journal_mode not in {"DELETE", "WAL", "MEMORY", "TRUNCATE", "PERSIST", "OFF"}:
        journal_mode = "MEMORY"
    try:
        conn.execute(f"PRAGMA journal_mode={journal_mode}")
    except sqlite3.DatabaseError:
        conn.execute("PRAGMA journal_mode=MEMORY")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: str = None) -> None:
    """Create all tables if they do not exist."""
    conn = _get_connection(db_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS encrypted_files (
            file_id          TEXT PRIMARY KEY,
            filename         TEXT NOT NULL,
            upload_timestamp TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS encrypted_index (
            token       TEXT NOT NULL,
            file_id     TEXT NOT NULL,
            token_type  TEXT NOT NULL DEFAULT 'K',
            score       REAL NOT NULL DEFAULT 0.0,
            FOREIGN KEY (file_id) REFERENCES encrypted_files(file_id)
                ON DELETE CASCADE
        )
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_token ON encrypted_index(token)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_token_type ON encrypted_index(token_type)")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS file_counter (
            counter_value INTEGER NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS search_history (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            search_time    TEXT NOT NULL,
            mode           TEXT NOT NULL,
            num_tokens     INTEGER NOT NULL,
            num_results    INTEGER NOT NULL,
            duration_ms    REAL NOT NULL,
            search_type    TEXT NOT NULL DEFAULT 'exact'
        )
    """)

    # --- Encrypted Records table ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS encrypted_records (
            record_id        TEXT PRIMARY KEY,
            record_type      TEXT NOT NULL DEFAULT 'text',
            encrypted_blob   BLOB NOT NULL,
            upload_timestamp TEXT NOT NULL,
            keywords_json    TEXT NOT NULL DEFAULT '[]'
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS record_index (
            token       TEXT NOT NULL,
            record_id   TEXT NOT NULL,
            token_type  TEXT NOT NULL DEFAULT 'K',
            score       REAL NOT NULL DEFAULT 0.0,
            FOREIGN KEY (record_id) REFERENCES encrypted_records(record_id)
                ON DELETE CASCADE
        )
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_rec_token ON record_index(token)")

    row = cur.execute("SELECT COUNT(*) FROM file_counter").fetchone()
    if row[0] == 0:
        cur.execute("INSERT INTO file_counter (counter_value) VALUES (0)")

    # Migrate: add token_type and score columns if missing (for existing DBs)
    try:
        cur.execute("SELECT token_type FROM encrypted_index LIMIT 1")
    except sqlite3.OperationalError:
        cur.execute("ALTER TABLE encrypted_index ADD COLUMN token_type TEXT NOT NULL DEFAULT 'K'")
        cur.execute("ALTER TABLE encrypted_index ADD COLUMN score REAL NOT NULL DEFAULT 0.0")

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# File operations
# ---------------------------------------------------------------------------

def add_file(file_id: str, filename: str, timestamp: str, db_path: str = None) -> None:
    conn = _get_connection(db_path)
    conn.execute(
        "INSERT INTO encrypted_files (file_id, filename, upload_timestamp) VALUES (?, ?, ?)",
        (file_id, filename, timestamp),
    )
    conn.commit()
    conn.close()


def list_files(db_path: str = None) -> list:
    conn = _get_connection(db_path)
    rows = conn.execute(
        "SELECT file_id, filename, upload_timestamp FROM encrypted_files"
    ).fetchall()
    conn.close()
    return [{"file_id": r[0], "filename": r[1], "upload_timestamp": r[2]} for r in rows]


def delete_file(file_id: str, storage_dir: str = "storage", db_path: str = None) -> bool:
    conn = _get_connection(db_path)
    cur = conn.cursor()
    row = cur.execute(
        "SELECT file_id FROM encrypted_files WHERE file_id = ?", (file_id,)
    ).fetchone()
    if row is None:
        conn.close()
        return False
    cur.execute("DELETE FROM encrypted_files WHERE file_id = ?", (file_id,))
    conn.commit()
    conn.close()
    enc_path = os.path.join(storage_dir, f"{file_id}.enc")
    if os.path.exists(enc_path):
        try:
            os.remove(enc_path)
        except OSError:
            # File may be locked by scanner/another process; DB state is already removed.
            pass
    return True


# ---------------------------------------------------------------------------
# Index operations (enhanced with token_type and score)
# ---------------------------------------------------------------------------

def add_tokens(token_entries: list, db_path: str = None) -> None:
    """Batch-insert token entries.

    Each entry is either:
      (token, file_id)                        — legacy 2-tuple
      (token, file_id, token_type, score)     — enhanced 4-tuple
    """
    conn = _get_connection(db_path)
    normalized = []
    for entry in token_entries:
        if len(entry) == 2:
            normalized.append((entry[0], entry[1], "K", 0.0))
        else:
            normalized.append((entry[0], entry[1], entry[2], entry[3]))
    conn.executemany(
        "INSERT INTO encrypted_index (token, file_id, token_type, score) VALUES (?, ?, ?, ?)",
        normalized,
    )
    conn.commit()
    conn.close()


def search_tokens(tokens: list, db_path: str = None) -> list:
    """Return file IDs matching ANY of the given tokens."""
    if not tokens:
        return []
    conn = _get_connection(db_path)
    placeholders = ",".join("?" for _ in tokens)
    rows = conn.execute(
        f"SELECT DISTINCT file_id FROM encrypted_index WHERE token IN ({placeholders})",
        tokens,
    ).fetchall()
    conn.close()
    return [r[0] for r in rows]


def search_tokens_with_scores(tokens: list, db_path: str = None) -> list:
    """Return (file_id, total_score, match_count) for tokens, ranked by score.

    Results are grouped by file_id, summing relevance scores and counting
    token matches. This enables TF-IDF ranked results.
    """
    if not tokens:
        return []
    conn = _get_connection(db_path)
    placeholders = ",".join("?" for _ in tokens)
    rows = conn.execute(
        f"""SELECT file_id,
                   SUM(score) as total_score,
                   COUNT(DISTINCT token) as match_count
            FROM encrypted_index
            WHERE token IN ({placeholders})
            GROUP BY file_id
            ORDER BY total_score DESC, match_count DESC""",
        tokens,
    ).fetchall()
    conn.close()
    return [{"file_id": r[0], "score": r[1], "match_count": r[2]} for r in rows]


def get_index_stats(db_path: str = None) -> dict:
    """Return statistics about the encrypted index."""
    conn = _get_connection(db_path)
    cur = conn.cursor()

    total = cur.execute("SELECT COUNT(*) FROM encrypted_index").fetchone()[0]
    k_count = cur.execute("SELECT COUNT(*) FROM encrypted_index WHERE token_type='K'").fetchone()[0]
    n_count = cur.execute("SELECT COUNT(*) FROM encrypted_index WHERE token_type='N'").fetchone()[0]
    b_count = cur.execute("SELECT COUNT(*) FROM encrypted_index WHERE token_type='B'").fetchone()[0]
    files = cur.execute("SELECT COUNT(*) FROM encrypted_files").fetchone()[0]

    conn.close()
    return {
        "total_tokens": total,
        "keyword_tokens": k_count,
        "ngram_tokens": n_count,
        "bigram_tokens": b_count,
        "total_files": files,
    }


# ---------------------------------------------------------------------------
# Search history
# ---------------------------------------------------------------------------

def add_search_record(search_time: str, mode: str, num_tokens: int,
                      num_results: int, duration_ms: float,
                      search_type: str = "exact", db_path: str = None) -> None:
    conn = _get_connection(db_path)
    conn.execute(
        """INSERT INTO search_history
           (search_time, mode, num_tokens, num_results, duration_ms, search_type)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (search_time, mode, num_tokens, num_results, duration_ms, search_type),
    )
    conn.commit()
    conn.close()


def get_search_history(limit: int = 50, db_path: str = None) -> list:
    conn = _get_connection(db_path)
    rows = conn.execute(
        """SELECT search_time, mode, num_tokens, num_results, duration_ms, search_type
           FROM search_history ORDER BY id DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    conn.close()
    return [{"time": r[0], "mode": r[1], "tokens": r[2],
             "results": r[3], "duration_ms": r[4], "type": r[5]} for r in rows]


# ---------------------------------------------------------------------------
# Record operations
# ---------------------------------------------------------------------------

def add_record(record_id: str, record_type: str, encrypted_blob: bytes,
               timestamp: str, keywords_json: str = "[]",
               db_path: str = None) -> None:
    conn = _get_connection(db_path)
    conn.execute(
        """INSERT INTO encrypted_records
           (record_id, record_type, encrypted_blob, upload_timestamp, keywords_json)
           VALUES (?, ?, ?, ?, ?)""",
        (record_id, record_type, encrypted_blob, timestamp, keywords_json),
    )
    conn.commit()
    conn.close()


def add_record_tokens(entries: list, db_path: str = None) -> None:
    """Batch-insert record index tokens (token, record_id, type, score)."""
    conn = _get_connection(db_path)
    conn.executemany(
        "INSERT INTO record_index (token, record_id, token_type, score) VALUES (?, ?, ?, ?)",
        entries,
    )
    conn.commit()
    conn.close()


def list_records(db_path: str = None) -> list:
    conn = _get_connection(db_path)
    rows = conn.execute(
        "SELECT record_id, record_type, upload_timestamp, keywords_json FROM encrypted_records"
    ).fetchall()
    conn.close()
    return [{"record_id": r[0], "record_type": r[1],
             "upload_timestamp": r[2], "keywords_json": r[3]} for r in rows]


def get_record_blob(record_id: str, db_path: str = None) -> bytes:
    conn = _get_connection(db_path)
    row = conn.execute(
        "SELECT encrypted_blob FROM encrypted_records WHERE record_id = ?",
        (record_id,),
    ).fetchone()
    conn.close()
    return row[0] if row else None


def delete_record(record_id: str, db_path: str = None) -> bool:
    conn = _get_connection(db_path)
    cur = conn.cursor()
    row = cur.execute(
        "SELECT record_id FROM encrypted_records WHERE record_id = ?",
        (record_id,),
    ).fetchone()
    if row is None:
        conn.close()
        return False
    cur.execute("DELETE FROM encrypted_records WHERE record_id = ?", (record_id,))
    conn.commit()
    conn.close()
    return True


def search_record_tokens(tokens: list, db_path: str = None) -> list:
    """Return record IDs matching any of the given tokens."""
    if not tokens:
        return []
    conn = _get_connection(db_path)
    placeholders = ",".join("?" for _ in tokens)
    rows = conn.execute(
        f"SELECT DISTINCT record_id FROM record_index WHERE token IN ({placeholders})",
        tokens,
    ).fetchall()
    conn.close()
    return [r[0] for r in rows]


def search_record_tokens_scored(tokens: list, db_path: str = None) -> list:
    """Return (record_id, total_score, match_count) ranked by score."""
    if not tokens:
        return []
    conn = _get_connection(db_path)
    placeholders = ",".join("?" for _ in tokens)
    rows = conn.execute(
        f"""SELECT record_id,
                   SUM(score) as total_score,
                   COUNT(DISTINCT token) as match_count
            FROM record_index
            WHERE token IN ({placeholders})
            GROUP BY record_id
            ORDER BY total_score DESC, match_count DESC""",
        tokens,
    ).fetchall()
    conn.close()
    return [{"record_id": r[0], "score": r[1], "match_count": r[2]} for r in rows]


def get_record_count(db_path: str = None) -> int:
    conn = _get_connection(db_path)
    row = conn.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()
    conn.close()
    return row[0]


def get_record_token_count(db_path: str = None) -> int:
    conn = _get_connection(db_path)
    row = conn.execute("SELECT COUNT(*) FROM record_index").fetchone()
    conn.close()
    return row[0]


# ---------------------------------------------------------------------------
# Counter operations
# ---------------------------------------------------------------------------

def get_counter(db_path: str = None) -> int:
    conn = _get_connection(db_path)
    row = conn.execute("SELECT counter_value FROM file_counter").fetchone()
    conn.close()
    return row[0] if row else 0


def increment_counter(db_path: str = None) -> int:
    conn = _get_connection(db_path)
    cur = conn.cursor()
    cur.execute("UPDATE file_counter SET counter_value = counter_value + 1")
    new_val = cur.execute("SELECT counter_value FROM file_counter").fetchone()[0]
    conn.commit()
    conn.close()
    return new_val
