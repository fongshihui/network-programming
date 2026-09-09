import os
import socket
import json
import mimetypes
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import unquote
import threading
from typing import Tuple, Optional, Dict, Any

from db import DatabaseManager
from security import (
    PasswordHasher,
    JWTManager,
    RateLimiter,
    InputValidator,
    TLSManager,
)
from cache import (
    HTTPCacheHelper,
    MultiTierCacheManager,
)

HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SERVER_PORT", 8080))
BUFFER_SIZE = 4096
PUBLIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public")
THREAD_POOL_SIZE = int(os.getenv("SERVER_WORKERS", 10))
ENABLE_TLS = os.getenv("ENABLE_TLS", "false").lower() in ("true", "1", "yes")


class HTTPRequest:
    """Represents a parsed HTTP Request."""
    def __init__(self, raw_data: bytes):
        self.method = ""
        self.path = ""
        self.query_string = ""
        self.version = ""
        self.headers: Dict[str, str] = {}
        self.body = b""
        self._parse(raw_data)

    def _parse(self, raw_data: bytes):
        parts = raw_data.split(b"\r\n\r\n", 1)
        header_part = parts[0].decode("iso-8859-1", errors="replace")
        if len(parts) > 1:
            self.body = parts[1]

        lines = header_part.split("\r\n")
        if not lines or not lines[0]:
            return

        request_line = lines[0].split()
        if len(request_line) >= 3:
            self.method = request_line[0].upper()
            full_path = request_line[1]
            self.version = request_line[2]

            if "?" in full_path:
                self.path, self.query_string = full_path.split("?", 1)
            else:
                self.path = full_path

            self.path = unquote(self.path)

        for line in lines[1:]:
            if ": " in line:
                key, val = line.split(": ", 1)
                self.headers[key.lower()] = val.strip()

    def get_auth_token(self) -> Optional[str]:
        """Extracts Bearer token from Authorization header."""
        auth = self.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return None


class HTTPResponse:
    """Builds a raw HTTP response."""
    STATUS_MESSAGES = {
        200: "OK",
        201: "Created",
        304: "Not Modified",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        422: "Unprocessable Entity",
        429: "Too Many Requests",
        500: "Internal Server Error",
    }

    @staticmethod
    def json(data: Any, status_code: int = 200, headers: Optional[dict] = None) -> Tuple[int, bytes]:
        body = json.dumps(data, indent=2).encode("utf-8")
        resp_headers = {
            "Content-Type": "application/json; charset=utf-8",
        }
        if headers:
            resp_headers.update(headers)
        return status_code, HTTPResponse.build(status_code, resp_headers, body)

    @staticmethod
    def html(content: str, status_code: int = 200, headers: Optional[dict] = None) -> Tuple[int, bytes]:
        body = content.encode("utf-8")
        resp_headers = {
            "Content-Type": "text/html; charset=utf-8",
        }
        if headers:
            resp_headers.update(headers)
        return status_code, HTTPResponse.build(status_code, resp_headers, body)

    @staticmethod
    def not_modified(etag: str) -> Tuple[int, bytes]:
        """Returns a 304 Not Modified HTTP response without body."""
        headers = {
            "ETag": etag,
            "Cache-Control": "public, max-age=30",
        }
        return 304, HTTPResponse.build(304, headers, b"")

    @staticmethod
    def build(status_code: int = 200, headers: Optional[dict] = None, body: bytes = b"") -> bytes:
        status_message = HTTPResponse.STATUS_MESSAGES.get(status_code, "Unknown")
        response_headers = {
            "Date": datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
            "Server": "SecureCustomSocketServer/5.0 (Python)",
            "Content-Length": str(len(body)),
            "Connection": "close",
        }
        if headers:
            response_headers.update(headers)

        header_lines = [f"HTTP/1.1 {status_code} {status_message}"]
        for k, v in response_headers.items():
            header_lines.append(f"{k}: {v}")

        header_bytes = ("\r\n".join(header_lines) + "\r\n\r\n").encode("iso-8859-1")
        return header_bytes + body


class HTTPServer:
    """
    HTTP Server implementing 5-phase network architecture:
      - Phase 1: Raw TCP Sockets & HTTP/1.1 protocol parsing
      - Phase 2: Application router connected to Database (MySQL + SQLite fallback)
      - Phase 3: Bounded Thread Pool concurrency architecture
      - Phase 4: Security (TLS, JWT Auth, RBAC, Rate Limiting, Input Validation)
      - Phase 5: Multi-tier Caching (HTTP ETag -> L1 Application -> L2 Redis -> MySQL)
    """
    def __init__(
        self,
        host: str = HOST,
        port: int = PORT,
        static_dir: str = PUBLIC_DIR,
        max_workers: int = THREAD_POOL_SIZE,
        enable_tls: bool = ENABLE_TLS,
    ):
        self.host = host
        self.port = port
        self.static_dir = static_dir
        self.max_workers = max_workers
        self.enable_tls = enable_tls

        # Phase 2: Database Layer
        self.db = DatabaseManager()

        # Phase 3: Concurrency Layer
        self.thread_pool = ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="HTTPWorker",
        )
        self.processed_requests = 0
        self._stats_lock = threading.Lock()

        # Phase 4: Security Layer
        self.rate_limiter = RateLimiter(default_limit=60, window_seconds=60)
        self.ssl_context = TLSManager.create_ssl_context() if self.enable_tls else None

        # Phase 5: Multi-tier Caching Layer
        self.cache_manager = MultiTierCacheManager()

    def start(self):
        protocol = "HTTPS" if self.enable_tls else "HTTP"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as base_sock:
            base_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            base_sock.bind((self.host, self.port))
            base_sock.listen(128)

            server_sock = base_sock
            if self.enable_tls and self.ssl_context:
                server_sock = self.ssl_context.wrap_socket(base_sock, server_side=True)

            print("=" * 70)
            print(f"🚀 {protocol} Server Started Successfully")
            print(f"📡 Address:        {protocol.lower()}://{self.host}:{self.port}")
            print(f"🧵 Concurrency:    Thread Pool ({self.max_workers} worker threads)")
            print(f"🔐 Security:       TLS={self.enable_tls} | Rate Limiting=Active | JWT Auth=Active")
            print(f"⚡ Caching:        HTTP (ETag) -> L1 App -> L2 {self.cache_manager.l2_redis.engine}")
            print(f"💾 Database:       {self.db.engine}")
            print(f"📂 Static Files:   {self.static_dir}")
            print("=" * 70 + "\n")

            try:
                while True:
                    client_sock, client_addr = server_sock.accept()
                    self.thread_pool.submit(self._handle_client, client_sock, client_addr)
            except KeyboardInterrupt:
                print("\n[!] Gracefully shutting down server and thread pool...")
                self.thread_pool.shutdown(wait=True)

    def _handle_client(self, client_sock: socket.socket, client_addr: tuple):
        """Worker task executed in the Thread Pool."""
        client_ip = client_addr[0]
        with client_sock:
            try:
                raw_data = b""
                while True:
                    chunk = client_sock.recv(BUFFER_SIZE)
                    raw_data += chunk
                    if len(chunk) < BUFFER_SIZE or b"\r\n\r\n" in raw_data:
                        break

                if not raw_data:
                    return

                request = HTTPRequest(raw_data)

                # Read remaining body according to Content-Length
                content_length = int(request.headers.get("content-length", 0))
                remaining_body = content_length - len(request.body)
                while remaining_body > 0:
                    chunk = client_sock.recv(min(BUFFER_SIZE, remaining_body))
                    if not chunk:
                        break
                    request.body += chunk
                    remaining_body -= len(chunk)

                # Phase 4: Rate Limiting Enforcement
                is_auth_endpoint = request.path.startswith("/api/auth/")
                limit = 15 if is_auth_endpoint else 60
                allowed, retry_after = self.rate_limiter.is_allowed(client_ip, limit=limit)
                if not allowed:
                    resp_headers = {"Retry-After": str(retry_after)}
                    status_code, response_data = HTTPResponse.json(
                        {"error": "Too Many Requests", "retry_after_seconds": retry_after},
                        429,
                        headers=resp_headers,
                    )
                    client_sock.sendall(response_data)
                    return

                # Application Routing
                status_code, response_data = self._route_request(request, client_ip)
                client_sock.sendall(response_data)

                with self._stats_lock:
                    self.processed_requests += 1

                current_thread = threading.current_thread().name
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}] [{current_thread}] {client_ip}:{client_addr[1]} - {request.method} {request.path} -> {status_code}")

            except Exception as e:
                print(f"[!] Error handling request from {client_addr}: {e}")
                err_response = HTTPResponse.build(500, {"Content-Type": "text/plain"}, b"500 Internal Server Error")
                try:
                    client_sock.sendall(err_response)
                except Exception:
                    pass

    def _authenticate_request(self, request: HTTPRequest) -> Optional[Dict[str, Any]]:
        """Extracts and verifies JWT token. Returns user payload or None."""
        token = request.get_auth_token()
        if not token:
            return None
        return JWTManager.verify_token(token)

    def _route_request(self, request: HTTPRequest, client_ip: str) -> Tuple[int, bytes]:
        """Application Router: Handles Authentication, Authorization, Caching, and DB."""

        # 1. System & Architecture Info
        if request.path == "/api/info" and request.method == "GET":
            payload = {
                "server": "Python Raw Socket Multi-Tier Server",
                "phases": {
                    "phase_1": "Low-level TCP Sockets & HTTP/1.1",
                    "phase_2": "Application Layer & Database Pooling",
                    "phase_3": "Bounded Thread Pool Concurrency",
                    "phase_4": "Security (TLS, JWT, RBAC, Rate Limiter, Input Validation)",
                    "phase_5": "Multi-tier Caching (HTTP -> App L1 -> Redis L2 -> DB)",
                },
                "tls_enabled": self.enable_tls,
                "thread_pool": {
                    "max_workers": self.max_workers,
                    "total_processed_requests": self.processed_requests,
                },
                "rate_limiter": self.rate_limiter.get_client_usage(client_ip),
                "caching": self.cache_manager.get_full_stats(),
                "database": self.db.get_info(),
            }
            return HTTPResponse.json(payload, 200)

        # 2. Phase 4: Authentication Endpoints
        # 2.1 POST /api/auth/register
        if request.path == "/api/auth/register" and request.method == "POST":
            try:
                body_data = json.loads(request.body.decode("utf-8")) if request.body else {}
            except Exception:
                return HTTPResponse.json({"error": "Invalid JSON format"}, 400)

            valid, err_msg, clean_data = InputValidator.validate_user_creation(body_data)
            if not valid:
                return HTTPResponse.json({"error": err_msg}, 422)

            if not clean_data["password"]:
                return HTTPResponse.json({"error": "Password is required for registration"}, 422)

            if self.db.get_user_by_email(clean_data["email"]):
                return HTTPResponse.json({"error": "User with this email already exists"}, 400)

            salt, p_hash = PasswordHasher.hash_password(clean_data["password"])
            user = self.db.create_user(
                clean_data["name"],
                clean_data["email"],
                password_hash=p_hash,
                salt=salt,
                role=clean_data["role"],
            )
            # Invalidate cached user lists
            self.cache_manager.invalidate("all_users")

            token = JWTManager.create_token(user["id"], user["email"], user["role"])
            return HTTPResponse.json({
                "message": "User registered successfully",
                "user": user,
                "access_token": token,
                "token_type": "Bearer",
            }, 201)

        # 2.2 POST /api/auth/login
        if request.path == "/api/auth/login" and request.method == "POST":
            try:
                body_data = json.loads(request.body.decode("utf-8")) if request.body else {}
            except Exception:
                return HTTPResponse.json({"error": "Invalid JSON format"}, 400)

            valid, err_msg, credentials = InputValidator.validate_login(body_data)
            if not valid:
                return HTTPResponse.json({"error": err_msg}, 422)

            user_record = self.db.get_user_by_email(credentials["email"])
            if not user_record or not user_record.get("password_hash") or not user_record.get("salt"):
                return HTTPResponse.json({"error": "Invalid email or password"}, 401)

            if not PasswordHasher.verify_password(credentials["password"], user_record["salt"], user_record["password_hash"]):
                return HTTPResponse.json({"error": "Invalid email or password"}, 401)

            token = JWTManager.create_token(user_record["id"], user_record["email"], user_record.get("role", "user"))
            return HTTPResponse.json({
                "message": "Login successful",
                "access_token": token,
                "token_type": "Bearer",
                "user": {
                    "id": user_record["id"],
                    "name": user_record["name"],
                    "email": user_record["email"],
                    "role": user_record.get("role", "user"),
                },
            }, 200)

        # 2.3 GET /api/auth/me (Protected User Profile)
        if request.path == "/api/auth/me" and request.method == "GET":
            auth_user = self._authenticate_request(request)
            if not auth_user:
                return HTTPResponse.json({"error": "Unauthorized: Valid Bearer token required"}, 401)

            user_id = int(auth_user["sub"])
            user_data = self.db.get_user_by_id(user_id)
            if not user_data:
                return HTTPResponse.json({"error": "User record not found"}, 404)

            return HTTPResponse.json({"authenticated_user": user_data, "jwt_claims": auth_user}, 200)

        # 3. Phase 5: Multi-Tier Cached Users API with HTTP ETags
        # 3.1 GET /api/users
        if request.path == "/api/users" and request.method == "GET":
            # Multi-tier fetch: L1 App Cache -> L2 Redis -> Database
            users, source = self.cache_manager.get_or_fetch(
                "all_users",
                fetch_fn=self.db.get_all_users,
                ttl=30,
            )

            response_payload = {
                "users": users,
                "count": len(users),
                "cache_tier_hit": source,
            }
            body_bytes = json.dumps(response_payload, indent=2).encode("utf-8")
            etag = HTTPCacheHelper.generate_etag(body_bytes)

            # Phase 5: HTTP Tier Validation (304 Not Modified)
            client_etag = request.headers.get("if-none-match")
            if HTTPCacheHelper.is_match(client_etag, etag):
                return HTTPResponse.not_modified(etag)

            headers = {
                "ETag": etag,
                "Cache-Control": "public, max-age=15",
                "X-Cache-Lookup": source,
            }
            return 200, HTTPResponse.build(200, {"Content-Type": "application/json; charset=utf-8", **headers}, body_bytes)

        # 3.2 POST /api/users (Create User - Requires Authentication)
        if request.path == "/api/users" and request.method == "POST":
            # Authorization: require authenticated user or admin
            auth_user = self._authenticate_request(request)
            if not auth_user:
                return HTTPResponse.json({"error": "Unauthorized: Please provide a valid Bearer token in Authorization header"}, 401)

            try:
                data = json.loads(request.body.decode("utf-8")) if request.body else {}
            except Exception:
                return HTTPResponse.json({"error": "Invalid JSON payload"}, 400)

            valid, err_msg, clean_data = InputValidator.validate_user_creation(data)
            if not valid:
                return HTTPResponse.json({"error": err_msg}, 422)

            if self.db.get_user_by_email(clean_data["email"]):
                return HTTPResponse.json({"error": "Email is already registered"}, 400)

            salt, p_hash = None, None
            if clean_data["password"]:
                salt, p_hash = PasswordHasher.hash_password(clean_data["password"])

            user = self.db.create_user(
                clean_data["name"],
                clean_data["email"],
                password_hash=p_hash,
                salt=salt,
                role=clean_data["role"],
            )

            # Phase 5: Invalidate Caches on mutation
            self.cache_manager.invalidate("all_users")

            return HTTPResponse.json({"message": "User created", "user": user, "cache_invalidated": True}, 201)

        # 3.3 DELETE /api/users/<id> (RBAC: Requires Admin Role)
        if request.path.startswith("/api/users/") and request.method == "DELETE":
            auth_user = self._authenticate_request(request)
            if not auth_user:
                return HTTPResponse.json({"error": "Unauthorized: Bearer token required"}, 401)

            # Phase 4 RBAC: Check Admin Role
            if auth_user.get("role") != "admin":
                return HTTPResponse.json({
                    "error": "Forbidden: Admin privileges required to delete users",
                    "your_role": auth_user.get("role"),
                }, 403)

            try:
                user_id = int(request.path.split("/")[-1])
                deleted = self.db.delete_user(user_id)
                if deleted:
                    # Invalidate caches
                    self.cache_manager.invalidate("all_users")
                    return HTTPResponse.json({"message": f"User {user_id} deleted successfully", "cache_invalidated": True}, 200)
                return HTTPResponse.json({"error": f"User {user_id} not found"}, 404)
            except ValueError:
                return HTTPResponse.json({"error": "Invalid user ID format"}, 400)

        # 4. Cache Management APIs
        if request.path == "/api/cache/stats" and request.method == "GET":
            return HTTPResponse.json(self.cache_manager.get_full_stats(), 200)

        if request.path == "/api/cache/flush" and request.method == "POST":
            self.cache_manager.l1_app.clear()
            self.cache_manager.l2_redis.flush()
            return HTTPResponse.json({"message": "All cache tiers (L1 App & L2 Redis) cleared successfully"}, 200)

        # 5. Echo API (POST)
        if request.path == "/api/echo" and request.method == "POST":
            try:
                parsed_json = json.loads(request.body.decode("utf-8")) if request.body else {}
                echo_payload = {
                    "message": "Echoed successfully",
                    "received": parsed_json,
                    "headers": request.headers,
                }
                return HTTPResponse.json(echo_payload, 200)
            except Exception as e:
                return HTTPResponse.json({"error": f"Invalid JSON payload: {str(e)}"}, 400)

        # 6. Static File Serving (GET only)
        if request.method != "GET":
            return HTTPResponse.html("<h1>405 Method Not Allowed</h1>", 405)

        rel_path = request.path.lstrip("/")
        if not rel_path or rel_path == "":
            rel_path = "index.html"

        # Security: Prevent directory traversal
        target_path = os.path.abspath(os.path.join(self.static_dir, rel_path))
        if not target_path.startswith(os.path.abspath(self.static_dir)):
            return HTTPResponse.html("<h1>403 Forbidden</h1>", 403)

        if os.path.isfile(target_path):
            content_type, _ = mimetypes.guess_type(target_path)
            content_type = content_type or "application/octet-stream"
            with open(target_path, "rb") as f:
                body = f.read()

            # HTTP Caching for Static Files
            etag = HTTPCacheHelper.generate_etag(body)
            client_etag = request.headers.get("if-none-match")
            if HTTPCacheHelper.is_match(client_etag, etag):
                return HTTPResponse.not_modified(etag)

            headers = {
                "Content-Type": content_type,
                "ETag": etag,
                "Cache-Control": "public, max-age=60",
            }
            return 200, HTTPResponse.build(200, headers, body)

        # 404 Not Found
        return HTTPResponse.html(
            "<!DOCTYPE html><html><body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p></body></html>",
            404,
        )


if __name__ == "__main__":
    server = HTTPServer(HOST, PORT)
    server.start()
