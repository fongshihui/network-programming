import os
import sqlite3
import queue
import threading
from contextlib import contextmanager
from typing import Optional, List, Dict, Any

# Try to import PyMySQL
try:
    import pymysql
    import pymysql.cursors
    PYMYSQL_AVAILABLE = True
except ImportError:
    PYMYSQL_AVAILABLE = False

from security import PasswordHasher


class DatabaseConfig:
    """Database configuration options."""
    HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
    PORT = int(os.getenv("MYSQL_PORT", 3306))
    USER = os.getenv("MYSQL_USER", "root")
    PASSWORD = os.getenv("MYSQL_PASSWORD", "")
    DATABASE = os.getenv("MYSQL_DATABASE", "network_prog_db")
    POOL_SIZE = int(os.getenv("DB_POOL_SIZE", 5))


class MySQLConnectionPool:
    """Thread-safe connection pool for MySQL."""
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self._pool = queue.Queue(maxsize=config.POOL_SIZE)
        self._lock = threading.Lock()
        self.is_connected = False
        self._init_pool()

    def _create_connection(self):
        return pymysql.connect(
            host=self.config.HOST,
            port=self.config.PORT,
            user=self.config.USER,
            password=self.config.PASSWORD,
            database=self.config.DATABASE,
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
            connect_timeout=3,
        )

    def _init_pool(self):
        if not PYMYSQL_AVAILABLE:
            self.is_connected = False
            return

        try:
            # First ensure database exists
            root_conn = pymysql.connect(
                host=self.config.HOST,
                port=self.config.PORT,
                user=self.config.USER,
                password=self.config.PASSWORD,
                autocommit=True,
                connect_timeout=3,
            )
            with root_conn.cursor() as cur:
                cur.execute(f"CREATE DATABASE IF NOT EXISTS `{self.config.DATABASE}`")
            root_conn.close()

            # Fill the pool
            for _ in range(self.config.POOL_SIZE):
                conn = self._create_connection()
                self._pool.put(conn)
            self.is_connected = True
        except Exception as e:
            self.is_connected = False
            self.error_msg = str(e)

    @contextmanager
    def get_connection(self):
        conn = self._pool.get(timeout=5)
        try:
            conn.ping(reconnect=True)
            yield conn
        finally:
            self._pool.put(conn)


class DatabaseManager:
    """
    Database access layer supporting both MySQL (with connection pooling)
    and SQLite fallback mode, with security schema (roles, password hashing).
    """
    def __init__(self):
        self.config = DatabaseConfig()
        self.mysql_pool = MySQLConnectionPool(self.config)
        self.engine = "MySQL" if self.mysql_pool.is_connected else "SQLite (Fallback)"
        self._sqlite_lock = threading.Lock()
        self._sqlite_path = os.path.join(os.path.dirname(__file__), "app.db")
        self._init_schema()
        self._seed_default_users()

    def _init_schema(self):
        if self.mysql_pool.is_connected:
            with self.mysql_pool.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS users (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            name VARCHAR(100) NOT NULL,
                            email VARCHAR(100) NOT NULL UNIQUE,
                            password_hash VARCHAR(128) DEFAULT NULL,
                            salt VARCHAR(64) DEFAULT NULL,
                            role VARCHAR(20) NOT NULL DEFAULT 'user',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
        else:
            with self._sqlite_lock:
                conn = sqlite3.connect(self._sqlite_path, check_same_thread=False)
                with conn:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT NOT NULL,
                            email TEXT NOT NULL UNIQUE,
                            password_hash TEXT DEFAULT NULL,
                            salt TEXT DEFAULT NULL,
                            role TEXT NOT NULL DEFAULT 'user',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                    # Check if columns need migration for existing db
                    cur = conn.cursor()
                    cur.execute("PRAGMA table_info(users)")
                    columns = [col[1] for col in cur.fetchall()]
                    if "password_hash" not in columns:
                        conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT DEFAULT NULL")
                    if "salt" not in columns:
                        conn.execute("ALTER TABLE users ADD COLUMN salt TEXT DEFAULT NULL")
                    if "role" not in columns:
                        conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
                conn.close()

    def _seed_default_users(self):
        """Seeds standard admin and test user if they don't already exist."""
        admin = self.get_user_by_email("admin@example.com")
        if not admin:
            salt, p_hash = PasswordHasher.hash_password("AdminPass123!")
            self.create_user("Administrator", "admin@example.com", password_hash=p_hash, salt=salt, role="admin")

        user = self.get_user_by_email("alice@example.com")
        if not user:
            salt, p_hash = PasswordHasher.hash_password("AlicePass123!")
            self.create_user("Alice Smith", "alice@example.com", password_hash=p_hash, salt=salt, role="user")

    def get_all_users(self) -> List[Dict[str, Any]]:
        """Retrieves safe user representation excluding password hashes."""
        if self.mysql_pool.is_connected:
            with self.mysql_pool.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, name, email, role, created_at FROM users ORDER BY id DESC")
                    results = cur.fetchall()
                    for r in results:
                        if "created_at" in r and r["created_at"]:
                            r["created_at"] = str(r["created_at"])
                    return results
        else:
            with self._sqlite_lock:
                conn = sqlite3.connect(self._sqlite_path, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT id, name, email, role, created_at FROM users ORDER BY id DESC")
                rows = cur.fetchall()
                results = [dict(row) for row in rows]
                conn.close()
                return results

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Retrieves user including auth fields for authentication checks."""
        email_clean = email.strip().lower()
        if self.mysql_pool.is_connected:
            with self.mysql_pool.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT id, name, email, password_hash, salt, role, created_at FROM users WHERE email = %s",
                        (email_clean,),
                    )
                    return cur.fetchone()
        else:
            with self._sqlite_lock:
                conn = sqlite3.connect(self._sqlite_path, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute(
                    "SELECT id, name, email, password_hash, salt, role, created_at FROM users WHERE email = ?",
                    (email_clean,),
                )
                row = cur.fetchone()
                res = dict(row) if row else None
                conn.close()
                return res

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        if self.mysql_pool.is_connected:
            with self.mysql_pool.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT id, name, email, role, created_at FROM users WHERE id = %s",
                        (user_id,),
                    )
                    return cur.fetchone()
        else:
            with self._sqlite_lock:
                conn = sqlite3.connect(self._sqlite_path, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute(
                    "SELECT id, name, email, role, created_at FROM users WHERE id = ?",
                    (user_id,),
                )
                row = cur.fetchone()
                res = dict(row) if row else None
                conn.close()
                return res

    def create_user(
        self,
        name: str,
        email: str,
        password_hash: Optional[str] = None,
        salt: Optional[str] = None,
        role: str = "user",
    ) -> Dict[str, Any]:
        email_clean = email.strip().lower()
        if self.mysql_pool.is_connected:
            with self.mysql_pool.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO users (name, email, password_hash, salt, role)
                        VALUES (%s, %s, %s, %s, %s)
                        """,
                        (name, email_clean, password_hash, salt, role),
                    )
                    user_id = cur.lastrowid
                    return {"id": user_id, "name": name, "email": email_clean, "role": role}
        else:
            with self._sqlite_lock:
                conn = sqlite3.connect(self._sqlite_path, check_same_thread=False)
                with conn:
                    cur = conn.cursor()
                    cur.execute(
                        """
                        INSERT INTO users (name, email, password_hash, salt, role)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (name, email_clean, password_hash, salt, role),
                    )
                    user_id = cur.lastrowid
                conn.close()
                return {"id": user_id, "name": name, "email": email_clean, "role": role}

    def delete_user(self, user_id: int) -> bool:
        if self.mysql_pool.is_connected:
            with self.mysql_pool.get_connection() as conn:
                with conn.cursor() as cur:
                    affected = cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
                    return affected > 0
        else:
            with self._sqlite_lock:
                conn = sqlite3.connect(self._sqlite_path, check_same_thread=False)
                with conn:
                    cur = conn.cursor()
                    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
                    affected = cur.rowcount
                conn.close()
                return affected > 0

    def get_info(self) -> dict:
        return {
            "engine": self.engine,
            "mysql_connected": self.mysql_pool.is_connected,
            "mysql_host": f"{self.config.HOST}:{self.config.PORT}" if self.mysql_pool.is_connected else None,
            "mysql_db": self.config.DATABASE if self.mysql_pool.is_connected else None,
        }
