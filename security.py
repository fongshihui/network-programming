import os
import re
import json
import base64
import hmac
import hashlib
import time
import ssl
import subprocess
import threading
from typing import Optional, Tuple, Dict, Any

# JWT Secret & Configuration
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-network-programming-key-2026")
JWT_EXPIRATION_SECONDS = int(os.getenv("JWT_EXPIRATION_SECONDS", 3600))  # 1 hour


class PasswordHasher:
    """Secure password hashing using PBKDF2-HMAC-SHA256."""

    ITERATIONS = 100_000

    @staticmethod
    def hash_password(password: str) -> Tuple[str, str]:
        """Returns (salt_hex, hash_hex)."""
        salt = os.urandom(16)
        pwd_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PasswordHasher.ITERATIONS,
        )
        return salt.hex(), pwd_hash.hex()

    @staticmethod
    def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
        """Verifies a password using constant-time comparison."""
        try:
            salt = bytes.fromhex(salt_hex)
            expected_hash = bytes.fromhex(hash_hex)
            computed_hash = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt,
                PasswordHasher.ITERATIONS,
            )
            return hmac.compare_digest(computed_hash, expected_hash)
        except Exception:
            return False


class JWTManager:
    """Lightweight RFC 7519 compliant JSON Web Token (HS256) implementation."""

    @staticmethod
    def _b64_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

    @staticmethod
    def _b64_decode(data: str) -> bytes:
        rem = len(data) % 4
        if rem > 0:
            data += "=" * (4 - rem)
        return base64.urlsafe_b64decode(data.encode("utf-8"))

    @classmethod
    def create_token(cls, user_id: int, email: str, role: str = "user") -> str:
        """Generates a signed HS256 JWT token."""
        header = {"alg": "HS256", "typ": "JWT"}
        now = int(time.time())
        payload = {
            "sub": str(user_id),
            "email": email,
            "role": role,
            "iat": now,
            "exp": now + JWT_EXPIRATION_SECONDS,
        }

        header_b64 = cls._b64_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_b64 = cls._b64_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

        signature = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
        signature_b64 = cls._b64_encode(signature)

        return f"{header_b64}.{payload_b64}.{signature_b64}"

    @classmethod
    def verify_token(cls, token: str) -> Optional[Dict[str, Any]]:
        """Verifies and decodes a JWT token. Returns payload dict or None."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            header_b64, payload_b64, signature_b64 = parts
            signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
            expected_sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
            actual_sig = cls._b64_decode(signature_b64)

            if not hmac.compare_digest(expected_sig, actual_sig):
                return None

            payload = json.loads(cls._b64_decode(payload_b64).decode("utf-8"))
            if payload.get("exp", 0) < int(time.time()):
                return None  # Expired

            return payload
        except Exception:
            return None


class RateLimiter:
    """
    Sliding window rate limiter with per-IP bucket tracking.
    Thread-safe implementation for multi-worker environments.
    """
    def __init__(self, default_limit: int = 60, window_seconds: int = 60):
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        self._requests: Dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, client_ip: str, limit: Optional[int] = None) -> Tuple[bool, int]:
        """
        Checks if client IP is within rate limits.
        Returns: (is_allowed: bool, retry_after_seconds: int)
        """
        max_limit = limit if limit is not None else self.default_limit
        now = time.time()
        window_start = now - self.window_seconds

        with self._lock:
            if client_ip not in self._requests:
                self._requests[client_ip] = []

            # Purge timestamps outside sliding window
            self._requests[client_ip] = [t for t in self._requests[client_ip] if t > window_start]

            if len(self._requests[client_ip]) >= max_limit:
                oldest = self._requests[client_ip][0]
                retry_after = max(1, int(oldest + self.window_seconds - now))
                return False, retry_after

            self._requests[client_ip].append(now)
            return True, 0

    def get_client_usage(self, client_ip: str) -> Dict[str, Any]:
        """Returns rate limiting metrics for an IP."""
        now = time.time()
        window_start = now - self.window_seconds
        with self._lock:
            timestamps = [t for t in self._requests.get(client_ip, []) if t > window_start]
            return {
                "ip": client_ip,
                "current_window_requests": len(timestamps),
                "limit": self.default_limit,
                "remaining": max(0, self.default_limit - len(timestamps)),
                "window_seconds": self.window_seconds,
            }


class InputValidator:
    """Strict input validation and sanitization."""

    EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

    @classmethod
    def validate_user_creation(cls, data: Any) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Validates payload for user creation."""
        if not isinstance(data, dict):
            return False, "Request body must be a JSON object", {}

        name = str(data.get("name", "")).strip()
        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", "")).strip()
        role = str(data.get("role", "user")).strip().lower()

        if not name or len(name) < 2 or len(name) > 80:
            return False, "Name is required and must be between 2 and 80 characters", {}

        if not email or len(email) > 120 or not cls.EMAIL_REGEX.match(email):
            return False, "A valid email address is required (e.g. user@example.com)", {}

        if password and len(password) < 6:
            return False, "Password must be at least 6 characters long", {}

        if role not in ("user", "admin"):
            role = "user"

        # Sanitize HTML tags
        name_clean = re.sub(r"[<>]", "", name)

        return True, None, {
            "name": name_clean,
            "email": email,
            "password": password if password else None,
            "role": role,
        }

    @classmethod
    def validate_login(cls, data: Any) -> Tuple[bool, Optional[str], Dict[str, str]]:
        """Validates login credentials payload."""
        if not isinstance(data, dict):
            return False, "Request body must be a JSON object", {}

        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", "")).strip()

        if not email or not cls.EMAIL_REGEX.match(email):
            return False, "Valid email required", {}

        if not password:
            return False, "Password is required", {}

        return True, None, {"email": email, "password": password}


class TLSManager:
    """Manages SSL/TLS context and self-signed certificate generation."""

    @staticmethod
    def ensure_certificate(cert_file: str = "cert.pem", key_file: str = "key.pem") -> Tuple[str, str]:
        """Generates a self-signed TLS certificate if one does not exist."""
        base_dir = os.path.dirname(os.path.abspath(__file__))
        cert_path = os.path.join(base_dir, cert_file)
        key_path = os.path.join(base_dir, key_file)

        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            print(f"[TLS] Generating self-signed certificate: {cert_file}, {key_file}...")
            cmd = [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path,
                "-out", cert_path,
                "-days", "365",
                "-nodes",
                "-subj", "/CN=localhost/O=NetworkProgramming/C=US",
            ]
            try:
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print("[TLS] Self-signed certificate generated successfully.")
            except Exception as e:
                print(f"[TLS] Failed to invoke openssl: {e}")

        return cert_path, key_path

    @staticmethod
    def create_ssl_context(cert_file: str = "cert.pem", key_file: str = "key.pem") -> Optional[ssl.SSLContext]:
        """Builds a secure SSLContext for the HTTPS server."""
        try:
            cert_path, key_path = TLSManager.ensure_certificate(cert_file, key_file)
            if not os.path.exists(cert_path) or not os.path.exists(key_path):
                return None

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            # Modern TLS settings
            ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            return ctx
        except Exception as e:
            print(f"[TLS] Error setting up SSL context: {e}")
            return None
