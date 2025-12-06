"""SQLite caching layer for CVE data."""

import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from blastauri.core.models import AffectedPackage, CVE, Ecosystem, Severity
from blastauri.utils.logging import get_logger

logger = get_logger(__name__)

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "blastauri"
DEFAULT_CACHE_FILE = "cve.db"
DEFAULT_TTL_SECONDS = 24 * 60 * 60


class CveCache:
    """SQLite-based cache for CVE data.

    Provides persistent caching with TTL to reduce API calls
    and improve performance.
    """

    def __init__(
        self,
        cache_dir: Path | None = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        """Initialize the CVE cache.

        Args:
            cache_dir: Directory for cache database.
            ttl_seconds: Time-to-live for cached entries in seconds.
        """
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self.ttl_seconds = ttl_seconds
        self.db_path = self.cache_dir / DEFAULT_CACHE_FILE
        self._connection: sqlite3.Connection | None = None

        self._ensure_cache_dir()
        self._init_database()

    def _ensure_cache_dir(self) -> None:
        """Ensure the cache directory exists."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        if self._connection is None:
            self._connection = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row
        return self._connection

    def _init_database(self) -> None:
        """Initialize the database schema."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                cve_id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                source TEXT NOT NULL,
                cached_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS package_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ecosystem TEXT NOT NULL,
                package_name TEXT NOT NULL,
                version TEXT,
                cve_ids TEXT NOT NULL,
                cached_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                UNIQUE(ecosystem, package_name, version)
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cve_expires
            ON cve_cache(expires_at)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_package_expires
            ON package_queries(expires_at)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_package_lookup
            ON package_queries(ecosystem, package_name, version)
        """)

        conn.commit()

    def get_cve(self, cve_id: str) -> CVE | None:
        """Get a CVE from cache.

        Args:
            cve_id: CVE identifier.

        Returns:
            Cached CVE or None if not found or expired.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        now = int(time.time())

        cursor.execute(
            """
            SELECT data FROM cve_cache
            WHERE cve_id = ? AND expires_at > ?
            """,
            (cve_id, now),
        )

        row = cursor.fetchone()
        if row:
            try:
                data = json.loads(row["data"])
                return self._deserialize_cve(data)
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning("Failed to deserialize cached CVE %s: %s", cve_id, e)
                self.delete_cve(cve_id)

        return None

    def set_cve(self, cve: CVE) -> None:
        """Store a CVE in cache.

        Args:
            cve: CVE to cache.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        now = int(time.time())
        expires_at = now + self.ttl_seconds

        data = self._serialize_cve(cve)

        cursor.execute(
            """
            INSERT OR REPLACE INTO cve_cache
            (cve_id, data, source, cached_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (cve.id, json.dumps(data), cve.source, now, expires_at),
        )

        conn.commit()

    def delete_cve(self, cve_id: str) -> None:
        """Delete a CVE from cache.

        Args:
            cve_id: CVE identifier.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM cve_cache WHERE cve_id = ?", (cve_id,))
        conn.commit()

    def get_package_cves(
        self,
        ecosystem: Ecosystem,
        package_name: str,
        version: str | None = None,
    ) -> list[CVE] | None:
        """Get cached CVEs for a package.

        Args:
            ecosystem: Package ecosystem.
            package_name: Package name.
            version: Optional version.

        Returns:
            List of cached CVEs or None if not found or expired.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        now = int(time.time())

        cursor.execute(
            """
            SELECT cve_ids FROM package_queries
            WHERE ecosystem = ? AND package_name = ? AND version IS ?
            AND expires_at > ?
            """,
            (ecosystem.value, package_name, version, now),
        )

        row = cursor.fetchone()
        if not row:
            return None

        try:
            cve_ids = json.loads(row["cve_ids"])
        except json.JSONDecodeError:
            return None

        cves: list[CVE] = []
        for cve_id in cve_ids:
            cve = self.get_cve(cve_id)
            if cve:
                cves.append(cve)

        return cves

    def set_package_cves(
        self,
        ecosystem: Ecosystem,
        package_name: str,
        cves: list[CVE],
        version: str | None = None,
    ) -> None:
        """Store CVEs for a package query.

        Args:
            ecosystem: Package ecosystem.
            package_name: Package name.
            cves: List of CVEs to cache.
            version: Optional version.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        now = int(time.time())
        expires_at = now + self.ttl_seconds

        for cve in cves:
            self.set_cve(cve)

        cve_ids = [cve.id for cve in cves]

        cursor.execute(
            """
            INSERT OR REPLACE INTO package_queries
            (ecosystem, package_name, version, cve_ids, cached_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                ecosystem.value,
                package_name,
                version,
                json.dumps(cve_ids),
                now,
                expires_at,
            ),
        )

        conn.commit()

    def clear_expired(self) -> int:
        """Remove expired entries from cache.

        Returns:
            Number of entries removed.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        now = int(time.time())

        cursor.execute("DELETE FROM cve_cache WHERE expires_at <= ?", (now,))
        cve_count = cursor.rowcount

        cursor.execute("DELETE FROM package_queries WHERE expires_at <= ?", (now,))
        query_count = cursor.rowcount

        conn.commit()

        total = cve_count + query_count
        if total > 0:
            logger.debug("Cleared %d expired cache entries", total)

        return total

    def clear_all(self) -> None:
        """Clear all cache entries."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM cve_cache")
        cursor.execute("DELETE FROM package_queries")

        conn.commit()
        logger.debug("Cleared all cache entries")

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache statistics.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        now = int(time.time())

        cursor.execute("SELECT COUNT(*) as total FROM cve_cache")
        total_cves = cursor.fetchone()["total"]

        cursor.execute(
            "SELECT COUNT(*) as valid FROM cve_cache WHERE expires_at > ?",
            (now,),
        )
        valid_cves = cursor.fetchone()["valid"]

        cursor.execute("SELECT COUNT(*) as total FROM package_queries")
        total_queries = cursor.fetchone()["total"]

        cursor.execute(
            "SELECT COUNT(*) as valid FROM package_queries WHERE expires_at > ?",
            (now,),
        )
        valid_queries = cursor.fetchone()["valid"]

        return {
            "total_cves": total_cves,
            "valid_cves": valid_cves,
            "expired_cves": total_cves - valid_cves,
            "total_package_queries": total_queries,
            "valid_package_queries": valid_queries,
            "expired_package_queries": total_queries - valid_queries,
            "db_path": str(self.db_path),
            "ttl_seconds": self.ttl_seconds,
        }

    def close(self) -> None:
        """Close the database connection."""
        if self._connection:
            self._connection.close()
            self._connection = None

    def _serialize_cve(self, cve: CVE) -> dict[str, Any]:
        """Serialize a CVE to a dictionary.

        Args:
            cve: CVE to serialize.

        Returns:
            Serialized dictionary.
        """
        return {
            "id": cve.id,
            "description": cve.description,
            "severity": cve.severity.value,
            "cvss_score": cve.cvss_score,
            "cvss_vector": cve.cvss_vector,
            "affected_packages": [
                {
                    "ecosystem": pkg.ecosystem.value,
                    "name": pkg.name,
                    "version_start": pkg.version_start,
                    "version_end": pkg.version_end,
                    "fixed_version": pkg.fixed_version,
                }
                for pkg in cve.affected_packages
            ],
            "references": cve.references,
            "published_date": cve.published_date.isoformat() if cve.published_date else None,
            "modified_date": cve.modified_date.isoformat() if cve.modified_date else None,
            "source": cve.source,
            "is_waf_mitigatable": cve.is_waf_mitigatable,
            "waf_pattern_id": cve.waf_pattern_id,
        }

    def _deserialize_cve(self, data: dict[str, Any]) -> CVE:
        """Deserialize a CVE from a dictionary.

        Args:
            data: Serialized dictionary.

        Returns:
            Deserialized CVE.
        """
        affected_packages = [
            AffectedPackage(
                ecosystem=Ecosystem(pkg["ecosystem"]),
                name=pkg["name"],
                version_start=pkg.get("version_start"),
                version_end=pkg.get("version_end"),
                fixed_version=pkg.get("fixed_version"),
            )
            for pkg in data.get("affected_packages", [])
        ]

        published_date = None
        if data.get("published_date"):
            published_date = datetime.fromisoformat(data["published_date"])

        modified_date = None
        if data.get("modified_date"):
            modified_date = datetime.fromisoformat(data["modified_date"])

        return CVE(
            id=data["id"],
            description=data["description"],
            severity=Severity(data["severity"]),
            cvss_score=data.get("cvss_score"),
            cvss_vector=data.get("cvss_vector"),
            affected_packages=affected_packages,
            references=data.get("references", []),
            published_date=published_date,
            modified_date=modified_date,
            source=data["source"],
            is_waf_mitigatable=data.get("is_waf_mitigatable", False),
            waf_pattern_id=data.get("waf_pattern_id"),
        )
