import os
import socket
import json
import mimetypes
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import unquote
import threading

from db import DatabaseManager

HOST = "127.0.0.1"
PORT = 8080
BUFFER_SIZE = 4096
PUBLIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public")
THREAD_POOL_SIZE = int(os.getenv("SERVER_WORKERS", 10))


class HTTPRequest:
    """Represents a parsed HTTP Request."""
    def __init__(self, raw_data: bytes):
        self.method = ""
        self.path = ""
        self.query_string = ""
        self.version = ""
        self.headers = {}
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


class HTTPResponse:
    """Builds a raw HTTP response."""
    STATUS_MESSAGES = {
        200: "OK",
        201: "Created",
        400: "Bad Request",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
    }

    @staticmethod
    def json(data: dict or list, status_code: int = 200) -> tuple[int, bytes]:
        body = json.dumps(data, indent=2).encode("utf-8")
        headers = {
            "Content-Type": "application/json; charset=utf-8",
        }
        return status_code, HTTPResponse.build(status_code, headers, body)

    @staticmethod
    def html(content: str, status_code: int = 200) -> tuple[int, bytes]:
        body = content.encode("utf-8")
        headers = {
            "Content-Type": "text/html; charset=utf-8",
        }
        return status_code, HTTPResponse.build(status_code, headers, body)

    @staticmethod
    def build(status_code: int = 200, headers: dict = None, body: bytes = b"") -> bytes:
        status_message = HTTPResponse.STATUS_MESSAGES.get(status_code, "Unknown")
        response_headers = {
            "Date": datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
            "Server": "CustomSocketServer/2.0 (Python)",
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
    HTTP Server implementing:
      - Phase 1: Raw TCP Sockets & HTTP/1.1 protocol parsing
      - Phase 2: Application router connected to MySQL (with fallback)
      - Phase 3: Bounded Thread Pool concurrency architecture
    """
    def __init__(
        self,
        host: str = HOST,
        port: int = PORT,
        static_dir: str = PUBLIC_DIR,
        max_workers: int = THREAD_POOL_SIZE,
    ):
        self.host = host
        self.port = port
        self.static_dir = static_dir
        self.max_workers = max_workers
        self.db = DatabaseManager()
        self.thread_pool = ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="HTTPWorker",
        )
        self.processed_requests = 0
        self._stats_lock = threading.Lock()

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.host, self.port))
            server_sock.listen(128)

            print("=" * 60)
            print("🚀 HTTP Server Started")
            print(f"📡 Address:        http://{self.host}:{self.port}")
            print(f"🧵 Concurrency:    Thread Pool ({self.max_workers} worker threads)")
            print(f"💾 Database:       {self.db.engine}")
            print(f"📂 Static Files:   {self.static_dir}")
            print("=" * 60 + "\n")

            try:
                while True:
                    client_sock, client_addr = server_sock.accept()
                    # Phase 3: Submit incoming socket connection to Thread Pool
                    self.thread_pool.submit(self._handle_client, client_sock, client_addr)
            except KeyboardInterrupt:
                print("\n[!] Gracefully shutting down thread pool and server...")
                self.thread_pool.shutdown(wait=True)

    def _handle_client(self, client_sock: socket.socket, client_addr: tuple):
        """Worker task executed in the Thread Pool."""
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

                # Application Routing -> MySQL
                status_code, response_data = self._route_request(request)
                client_sock.sendall(response_data)

                with self._stats_lock:
                    self.processed_requests += 1

                current_thread = threading.current_thread().name
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}] [{current_thread}] {client_addr[0]}:{client_addr[1]} - {request.method} {request.path} -> {status_code}")

            except Exception as e:
                print(f"[!] Error handling request from {client_addr}: {e}")
                err_response = HTTPResponse.build(500, {"Content-Type": "text/plain"}, b"500 Internal Server Error")
                try:
                    client_sock.sendall(err_response)
                except Exception:
                    pass

    def _route_request(self, request: HTTPRequest) -> tuple[int, bytes]:
        """Application Layer: routes requests to business logic / Database."""

        # 1. System & Concurrency Info
        if request.path == "/api/info" and request.method == "GET":
            payload = {
                "server": "Python Raw Socket HTTP Server",
                "architecture": "HTTP -> Thread Pool -> MySQL",
                "time": datetime.utcnow().isoformat() + "Z",
                "thread_pool": {
                    "max_workers": self.max_workers,
                    "total_processed_requests": self.processed_requests,
                },
                "database": self.db.get_info(),
            }
            return HTTPResponse.json(payload, 200)

        # 2. Users API (CRUD) -> Database
        if request.path == "/api/users":
            if request.method == "GET":
                users = self.db.get_all_users()
                return HTTPResponse.json({"users": users, "count": len(users)}, 200)

            elif request.method == "POST":
                try:
                    data = json.loads(request.body.decode("utf-8")) if request.body else {}
                    name = data.get("name", "").strip()
                    email = data.get("email", "").strip()
                    if not name or not email:
                        return HTTPResponse.json({"error": "Fields 'name' and 'email' are required"}, 400)

                    user = self.db.create_user(name, email)
                    return HTTPResponse.json({"message": "User created", "user": user}, 201)
                except Exception as e:
                    return HTTPResponse.json({"error": str(e)}, 400)

        # 3. User Deletion by ID: DELETE /api/users/<id>
        if request.path.startswith("/api/users/") and request.method == "DELETE":
            try:
                user_id = int(request.path.split("/")[-1])
                deleted = self.db.delete_user(user_id)
                if deleted:
                    return HTTPResponse.json({"message": f"User {user_id} deleted successfully"}, 200)
                return HTTPResponse.json({"error": f"User {user_id} not found"}, 404)
            except ValueError:
                return HTTPResponse.json({"error": "Invalid user ID"}, 400)

        # 4. Echo API (POST)
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

        # 5. Static File Serving (GET only)
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
            return 200, HTTPResponse.build(200, {"Content-Type": content_type}, body)

        # 404 Not Found
        return HTTPResponse.html(
            "<!DOCTYPE html><html><body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p></body></html>",
            404,
        )


if __name__ == "__main__":
    server = HTTPServer(HOST, PORT)
    server.start()
