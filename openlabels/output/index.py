"""
OpenLabels Label Index.

SQLite-based index for storing and resolving virtual labels.

The index stores the full LabelSet data for files using virtual labels
(xattr pointers). It supports:
- Storage and retrieval by labelID
- Version tracking via content_hash
- Querying by entity type, risk score, etc.

Per the spec, the index MUST NOT leave the user's tenant.
"""

import json
import sqlite3
import logging
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
from contextlib import contextmanager

from ..core.labels import LabelSet, VirtualLabelPointer

logger = logging.getLogger(__name__)


class DatabaseError(Exception):
    """Database operation failed - may be retryable."""
    pass


class CorruptedDataError(Exception):
    """Data in database is corrupted or invalid."""
    pass


# JSON Schema for LabelSet validation
LABEL_SET_SCHEMA = {
    "type": "object",
    "required": ["labelID", "content_hash", "labels", "source"],
    "properties": {
        "labelID": {"type": "string", "minLength": 1},
        "content_hash": {"type": "string", "minLength": 1},
        "source": {"type": "string"},
        "created_at": {"type": "string"},
        "labels": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["type"],
                "properties": {
                    "type": {"type": "string"},
                    "count": {"type": "integer", "minimum": 0},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "source": {"type": "string"},
                    "spans": {"type": "array"},
                }
            }
        }
    }
}


def _validate_label_json(json_str: str) -> dict:
    """
    Validate and parse label JSON data.

    Args:
        json_str: JSON string from database

    Returns:
        Parsed and validated dict

    Raises:
        CorruptedDataError: If JSON is malformed or fails schema validation
    """
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise CorruptedDataError(f"Malformed JSON in database: {e}")

    # Basic schema validation (without external dependency)
    if not isinstance(data, dict):
        raise CorruptedDataError("Label data must be an object")

    required_fields = ["labelID", "content_hash", "labels", "source"]
    for field in required_fields:
        if field not in data:
            raise CorruptedDataError(f"Missing required field: {field}")

    if not isinstance(data.get("labelID"), str) or not data["labelID"]:
        raise CorruptedDataError("labelID must be a non-empty string")

    if not isinstance(data.get("content_hash"), str) or not data["content_hash"]:
        raise CorruptedDataError("content_hash must be a non-empty string")

    if not isinstance(data.get("labels"), list):
        raise CorruptedDataError("labels must be an array")

    # Validate each label entry
    for i, label in enumerate(data["labels"]):
        if not isinstance(label, dict):
            raise CorruptedDataError(f"labels[{i}] must be an object")
        if "type" not in label or not isinstance(label.get("type"), str):
            raise CorruptedDataError(f"labels[{i}].type must be a string")
        if "count" in label and not isinstance(label.get("count"), int):
            raise CorruptedDataError(f"labels[{i}].count must be an integer")
        if "confidence" in label:
            conf = label.get("confidence")
            if not isinstance(conf, (int, float)) or conf < 0 or conf > 1:
                raise CorruptedDataError(
                    f"labels[{i}].confidence must be a number between 0 and 1"
                )

    return data

# Default index location
DEFAULT_INDEX_PATH = Path.home() / ".openlabels" / "index.db"


class LabelIndex:
    """
    SQLite-based label index for virtual label resolution.

    The index stores:
    - label_objects: Core identity (labelID, tenant, created_at)
    - label_versions: Version history (content_hash, labels, risk_score)

    Usage:
        >>> index = LabelIndex()
        >>> index.store(label_set)
        >>> retrieved = index.get(label_id, content_hash)
    """

    SCHEMA_VERSION = 1

    def __init__(
        self,
        db_path: Optional[str] = None,
        tenant_id: str = "default",
    ):
        """
        Initialize the label index.

        Args:
            db_path: Path to SQLite database. If None, uses default location.
            tenant_id: Tenant identifier for multi-tenant isolation.
        """
        self.db_path = Path(db_path) if db_path else DEFAULT_INDEX_PATH
        self.tenant_id = tenant_id
        self._connection: Optional[sqlite3.Connection] = None

        # Ensure directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        with self._get_connection() as conn:
            conn.executescript("""
                -- Schema version tracking
                CREATE TABLE IF NOT EXISTS schema_info (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );

                -- Core label identity (immutable once created)
                CREATE TABLE IF NOT EXISTS label_objects (
                    label_id    TEXT PRIMARY KEY,
                    tenant_id   TEXT NOT NULL,
                    created_at  TEXT NOT NULL,
                    file_path   TEXT,
                    file_name   TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_label_objects_tenant
                    ON label_objects(tenant_id);

                -- Version history (append-only, one row per content_hash)
                CREATE TABLE IF NOT EXISTS label_versions (
                    label_id      TEXT NOT NULL,
                    content_hash  TEXT NOT NULL,
                    scanned_at    TEXT NOT NULL,
                    labels_json   TEXT NOT NULL,
                    source        TEXT NOT NULL,
                    risk_score    INTEGER,
                    risk_tier     TEXT,
                    entity_types  TEXT,
                    PRIMARY KEY (label_id, content_hash),
                    FOREIGN KEY (label_id) REFERENCES label_objects(label_id)
                );
                CREATE INDEX IF NOT EXISTS idx_label_versions_hash
                    ON label_versions(content_hash);
                CREATE INDEX IF NOT EXISTS idx_label_versions_score
                    ON label_versions(risk_score);
                CREATE INDEX IF NOT EXISTS idx_label_versions_scanned
                    ON label_versions(scanned_at);

                -- File path mapping for quick lookup
                CREATE TABLE IF NOT EXISTS file_mappings (
                    file_path     TEXT PRIMARY KEY,
                    label_id      TEXT NOT NULL,
                    content_hash  TEXT NOT NULL,
                    updated_at    TEXT NOT NULL,
                    FOREIGN KEY (label_id) REFERENCES label_objects(label_id)
                );
                CREATE INDEX IF NOT EXISTS idx_file_mappings_label
                    ON file_mappings(label_id);
            """)

            # Set schema version
            conn.execute(
                "INSERT OR REPLACE INTO schema_info (key, value) VALUES (?, ?)",
                ("schema_version", str(self.SCHEMA_VERSION)),
            )
            conn.commit()

    @contextmanager
    def _get_connection(self):
        """Get database connection with context management."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def _transaction(self, conn):
        """
        Execute operations within an explicit transaction.

        Uses BEGIN IMMEDIATE to acquire write lock upfront, preventing
        deadlocks in multi-writer scenarios. Automatically rolls back
        on exception and commits on success.

        Args:
            conn: SQLite connection

        Yields:
            The connection for executing statements

        Raises:
            DatabaseError: If transaction fails
        """
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except sqlite3.Error as e:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass  # Rollback failed, but we'll raise the original error
            raise DatabaseError(f"Transaction failed: {e}") from e
        except Exception:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise

    def store(
        self,
        label_set: LabelSet,
        file_path: Optional[str] = None,
        risk_score: Optional[int] = None,
        risk_tier: Optional[str] = None,
    ) -> bool:
        """
        Store a LabelSet in the index.

        Creates or updates the label object and adds a new version record.

        Args:
            label_set: The LabelSet to store
            file_path: Optional file path for mapping
            risk_score: Optional computed risk score
            risk_tier: Optional risk tier (MINIMAL, LOW, MEDIUM, HIGH, CRITICAL)

        Returns:
            True if successful, False otherwise
        """
        now = datetime.utcnow().isoformat()
        entity_types = ','.join(sorted(set(l.type for l in label_set.labels)))

        try:
            with self._get_connection() as conn:
                with self._transaction(conn):
                    # Upsert label object
                    conn.execute("""
                        INSERT INTO label_objects (label_id, tenant_id, created_at, file_path, file_name)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(label_id) DO UPDATE SET
                            file_path = COALESCE(excluded.file_path, file_path),
                            file_name = COALESCE(excluded.file_name, file_name)
                    """, (
                        label_set.label_id,
                        self.tenant_id,
                        now,
                        file_path,
                        Path(file_path).name if file_path else None,
                    ))

                    # Insert version (or update if same content_hash)
                    conn.execute("""
                        INSERT INTO label_versions
                            (label_id, content_hash, scanned_at, labels_json, source,
                             risk_score, risk_tier, entity_types)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(label_id, content_hash) DO UPDATE SET
                            scanned_at = excluded.scanned_at,
                            labels_json = excluded.labels_json,
                            source = excluded.source,
                            risk_score = COALESCE(excluded.risk_score, risk_score),
                            risk_tier = COALESCE(excluded.risk_tier, risk_tier),
                            entity_types = excluded.entity_types
                    """, (
                        label_set.label_id,
                        label_set.content_hash,
                        now,
                        label_set.to_json(compact=True),
                        label_set.source,
                        risk_score,
                        risk_tier,
                        entity_types,
                    ))

                    # Update file mapping if path provided
                    if file_path:
                        conn.execute("""
                            INSERT INTO file_mappings (file_path, label_id, content_hash, updated_at)
                            VALUES (?, ?, ?, ?)
                            ON CONFLICT(file_path) DO UPDATE SET
                                label_id = excluded.label_id,
                                content_hash = excluded.content_hash,
                                updated_at = excluded.updated_at
                        """, (
                            file_path,
                            label_set.label_id,
                            label_set.content_hash,
                            now,
                        ))

                return True

        except DatabaseError as e:
            logger.error(f"Failed to store label: {e}")
            return False
        except sqlite3.Error as e:
            logger.error(f"Failed to store label: {e}")
            return False

    def get(
        self,
        label_id: str,
        content_hash: Optional[str] = None,
    ) -> Optional[LabelSet]:
        """
        Retrieve a LabelSet from the index.

        Args:
            label_id: The label ID to look up
            content_hash: Optional specific version. If None, returns latest.

        Returns:
            LabelSet if found, None otherwise
        """
        try:
            with self._get_connection() as conn:
                if content_hash:
                    # Get specific version
                    row = conn.execute("""
                        SELECT labels_json FROM label_versions
                        WHERE label_id = ? AND content_hash = ?
                    """, (label_id, content_hash)).fetchone()
                else:
                    # Get latest version
                    row = conn.execute("""
                        SELECT labels_json FROM label_versions
                        WHERE label_id = ?
                        ORDER BY scanned_at DESC
                        LIMIT 1
                    """, (label_id,)).fetchone()

                if row:
                    # Validate JSON before deserializing
                    validated_data = _validate_label_json(row['labels_json'])
                    return LabelSet.from_dict(validated_data)
                return None

        except CorruptedDataError as e:
            logger.error(f"Corrupted label data for {label_id}: {e}")
            return None
        except sqlite3.Error as e:
            logger.error(f"Failed to get label: {e}")
            return None

    def get_by_path(self, file_path: str) -> Optional[LabelSet]:
        """
        Retrieve a LabelSet by file path.

        Args:
            file_path: The file path to look up

        Returns:
            LabelSet if found, None otherwise
        """
        try:
            with self._get_connection() as conn:
                row = conn.execute("""
                    SELECT v.labels_json
                    FROM file_mappings m
                    JOIN label_versions v ON m.label_id = v.label_id
                        AND m.content_hash = v.content_hash
                    WHERE m.file_path = ?
                """, (file_path,)).fetchone()

                if row:
                    # Validate JSON before deserializing
                    validated_data = _validate_label_json(row['labels_json'])
                    return LabelSet.from_dict(validated_data)
                return None

        except CorruptedDataError as e:
            logger.error(f"Corrupted label data for path {file_path}: {e}")
            return None
        except sqlite3.Error as e:
            logger.error(f"Failed to get label by path: {e}")
            return None

    def resolve(self, pointer: VirtualLabelPointer) -> Optional[LabelSet]:
        """
        Resolve a virtual label pointer to a full LabelSet.

        Args:
            pointer: VirtualLabelPointer from xattr

        Returns:
            LabelSet if found, None otherwise
        """
        return self.get(pointer.label_id, pointer.content_hash)

    def get_versions(self, label_id: str) -> List[Dict[str, Any]]:
        """
        Get all versions of a label.

        Args:
            label_id: The label ID

        Returns:
            List of version metadata dicts
        """
        try:
            with self._get_connection() as conn:
                rows = conn.execute("""
                    SELECT content_hash, scanned_at, source, risk_score, risk_tier, entity_types
                    FROM label_versions
                    WHERE label_id = ?
                    ORDER BY scanned_at DESC
                """, (label_id,)).fetchall()

                return [dict(row) for row in rows]

        except sqlite3.Error as e:
            logger.error(f"Failed to get versions: {e}")
            return []

    def query(
        self,
        min_score: Optional[int] = None,
        max_score: Optional[int] = None,
        risk_tier: Optional[str] = None,
        entity_type: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Query the index for labels matching criteria.

        Args:
            min_score: Minimum risk score
            max_score: Maximum risk score
            risk_tier: Risk tier filter
            entity_type: Entity type filter (e.g., "SSN")
            since: ISO timestamp for scanned_at filter
            limit: Maximum results

        Returns:
            List of matching label metadata
        """
        params: List[Any] = []

        base_query = """
            SELECT
                o.label_id,
                o.file_path,
                o.file_name,
                v.content_hash,
                v.scanned_at,
                v.risk_score,
                v.risk_tier,
                v.entity_types
            FROM label_objects o
            JOIN label_versions v ON o.label_id = v.label_id
            WHERE 1=1
        """

        if min_score is not None:
            base_query += " AND v.risk_score >= ?"
            params.append(min_score)

        if max_score is not None:
            base_query += " AND v.risk_score <= ?"
            params.append(max_score)

        if risk_tier:
            base_query += " AND v.risk_tier = ?"
            params.append(risk_tier)

        if entity_type:
            base_query += " AND v.entity_types LIKE ?"
            params.append("%" + entity_type + "%")

        if since:
            base_query += " AND v.scanned_at >= ?"
            params.append(since)

        base_query += " ORDER BY v.scanned_at DESC LIMIT ?"
        params.append(limit)

        try:
            with self._get_connection() as conn:
                rows = conn.execute(base_query, params).fetchall()
                return [dict(row) for row in rows]

        except sqlite3.Error as e:
            logger.error(f"Query failed: {e}")
            return []

    def delete(self, label_id: str) -> bool:
        """
        Delete a label and all its versions.

        Args:
            label_id: The label ID to delete

        Returns:
            True if deleted, False otherwise
        """
        try:
            with self._get_connection() as conn:
                with self._transaction(conn):
                    conn.execute(
                        "DELETE FROM file_mappings WHERE label_id = ?",
                        (label_id,),
                    )
                    conn.execute(
                        "DELETE FROM label_versions WHERE label_id = ?",
                        (label_id,),
                    )
                    conn.execute(
                        "DELETE FROM label_objects WHERE label_id = ?",
                        (label_id,),
                    )
                return True

        except DatabaseError as e:
            logger.error(f"Delete failed: {e}")
            return False
        except sqlite3.Error as e:
            logger.error(f"Delete failed: {e}")
            return False

    def count(self) -> Dict[str, int]:
        """Get counts of labels and versions."""
        try:
            with self._get_connection() as conn:
                labels = conn.execute(
                    "SELECT COUNT(*) FROM label_objects WHERE tenant_id = ?",
                    (self.tenant_id,),
                ).fetchone()[0]

                versions = conn.execute(
                    """SELECT COUNT(*) FROM label_versions v
                       JOIN label_objects o ON v.label_id = o.label_id
                       WHERE o.tenant_id = ?""",
                    (self.tenant_id,),
                ).fetchone()[0]

                return {"labels": labels, "versions": versions}

        except sqlite3.Error as e:
            logger.error(f"Count failed: {e}")
            return {"labels": 0, "versions": 0}

    def export(self, output_path: str) -> bool:
        """
        Export all labels to a JSONL file.

        Args:
            output_path: Path to output file

        Returns:
            True if successful
        """
        try:
            with self._get_connection() as conn:
                rows = conn.execute("""
                    SELECT v.labels_json, v.risk_score, v.risk_tier, o.file_path
                    FROM label_versions v
                    JOIN label_objects o ON v.label_id = o.label_id
                    WHERE o.tenant_id = ?
                """, (self.tenant_id,)).fetchall()

                with open(output_path, 'w') as f:
                    for row in rows:
                        record = json.loads(row['labels_json'])
                        record['_risk_score'] = row['risk_score']
                        record['_risk_tier'] = row['risk_tier']
                        record['_file_path'] = row['file_path']
                        f.write(json.dumps(record) + '\n')

                return True

        except (sqlite3.Error, OSError) as e:
            logger.error(f"Export failed: {e}")
            return False


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

_default_index: Optional[LabelIndex] = None
_default_index_lock = threading.Lock()


def get_default_index() -> LabelIndex:
    """Get the default label index singleton (thread-safe)."""
    global _default_index
    if _default_index is None:
        with _default_index_lock:
            # Double-check inside lock
            if _default_index is None:
                _default_index = LabelIndex()
    return _default_index


def store_label(
    label_set: LabelSet,
    file_path: Optional[str] = None,
    risk_score: Optional[int] = None,
    risk_tier: Optional[str] = None,
) -> bool:
    """Store a label in the default index."""
    return get_default_index().store(label_set, file_path, risk_score, risk_tier)


def get_label(
    label_id: str,
    content_hash: Optional[str] = None,
) -> Optional[LabelSet]:
    """Get a label from the default index."""
    return get_default_index().get(label_id, content_hash)


def resolve_pointer(pointer: VirtualLabelPointer) -> Optional[LabelSet]:
    """Resolve a virtual label pointer using the default index."""
    return get_default_index().resolve(pointer)
