import os
import sqlite3
import queue
import threading
from contextlib import contextmanager

# Try to import PyMySQL
try:
    import pymysql
    import pymysql.cursors
    PYMYSQL_AVAILABLE = True
except ImportError:
    PYMYSQL_AVAILABLE = False


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
    Database access layer.
    Prioritizes MySQL with thread-safe connection pooling.
    Falls back to SQLite if MySQL is offline or not configured.
    """
    def __init__(self):
        self.config = DatabaseConfig()
        self.mysql_pool = MySQLConnectionPool(self.config)
        self.engine = "MySQL" if self.mysql_pool.is_connected else "SQLite (Fallback)"
        self._sqlite_lock = threading.Lock()
        self._sqlite_path = os.path.join(os.path.dirname(__file__), "app.db")
        self._init_schema()

    def _init_schema(self):
        if self.mysql_pool.is_connected:
            with self.mysql_pool.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS users (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            name VARCHAR(100) NOT NULL,
                            email VARCHAR(100) NOT NULL UNIQUE,
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
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                conn.close()

    def get_all_users(self) -> list[dict]:
        if self.mysql_pool.is_connected:
            with self.mysql_pool.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, name, email, created_at FROM users ORDER BY id DESC")
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
                cur.execute("SELECT id, name, email, created_at FROM users ORDER BY id DESC")
                rows = cur.fetchall()
                results = [dict(row) for row in rows]
                conn.close()
                return results

    def create_user(self, name: str, email: str) -> dict:
        if self.mysql_pool.is_connected:
            with self.mysql_pool.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO users (name, email) VALUES (%s, %s)",
                        (name, email),
                    )
                    user_id = cur.lastrowid
                    return {"id": user_id, "name": name, "email": email}
        else:
            with self._sqlite_lock:
                conn = sqlite3.connect(self._sqlite_path, check_same_thread=False)
                with conn:
                    cur = conn.cursor()
                    cur.execute(
                        "INSERT INTO users (name, email) VALUES (?, ?)",
                        (name, email),
                    )
                    user_id = cur.lastrowid
                conn.close()
                return {"id": user_id, "name": name, "email": email}

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
