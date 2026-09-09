# Network Programming Multi-Tier Server

A complete end-to-end, multi-tier network server built from scratch using raw Python TCP sockets with low-level HTTP parsing, bounded thread pool concurrency, multi-tier security, and hierarchical caching.

---

## 🏗️ 5-Tier Architecture Overview

```
                          Client Browser / cURL / Postman
                                         │ (TCP / TLS Handshake)
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ Phase 1 & 4: Low-Level Socket & TLS Listener (server.py)                         │
│ - Raw TCP socket.bind(), socket.listen(), socket.accept()                        │
│ - TLS/HTTPS encryption termination via ssl.SSLContext                           │
│ - HTTP/1.1 Request & Response RFC parsing                                        │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ Phase 3 & 4: Concurrency & Security Gateways                                     │
│ - Bounded Thread Pool (ThreadPoolExecutor with max_workers)                      │
│ - Sliding-Window Per-IP Rate Limiting (429 Too Many Requests)                     │
│ - Input Validation & Sanitization (XSS/Payload checks)                           │
│ - JWT Authentication (HS256) & Role-Based Access Control (RBAC)                  │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ Phase 5: Multi-Tier Caching Pipeline                                             │
│                                                                                  │
│   [ HTTP Tier ]         --> ETag & Cache-Control validation (304 Not Modified)   │
│         │                                                                        │
│         ▼                                                                        │
│   [ L1 App Cache ]      --> In-Memory Thread-Safe TTL Cache (Microsecond lookup) │
│         │                                                                        │
│         ▼                                                                        │
│   [ L2 Redis Cache ]    --> Distributed Redis Key-Value Store (Sub-millisecond)  │
│         │                                                                        │
│         ▼                                                                        │
│   [ Database Tier ]     --> MySQL Connection Pool (with SQLite fallback)         │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Features by Phase

### Phase 1: Low-Level TCP Socket & HTTP/1.1 Engine
- Built directly on Python `socket` module without external web frameworks.
- Custom HTTP/1.1 streaming request parser (headers, body content-length, URL decoding).
- RFC-compliant HTTP response builder with status codes (`200`, `201`, `304`, `400`, `401`, `403`, `404`, `422`, `429`, `500`).

### Phase 2: Database Layer & Connection Pooling
- **MySQL Connection Pool**: Thread-safe `queue.Queue` connection pool for high-concurrency reuse.
- **Resilient Fallback**: Automatically falls back to embedded SQLite (`app.db`) if MySQL is offline.

### Phase 3: Bounded Thread Pool Concurrency
- Uses `ThreadPoolExecutor` with configurable worker threads (`SERVER_WORKERS`).
- Prevents resource exhaustion and thread-creation overhead under heavy connection loads.

### Phase 4: Multi-Tier Security
- **TLS / HTTPS**: Optional TLS socket wrapper (`ssl.SSLContext`) with auto-generated self-signed certificates.
- **Authentication**: PBKDF2-HMAC-SHA256 password hashing with 100,000 iterations and 16-byte random salts.
- **JWT (JSON Web Tokens)**: RFC 7519 HS256 signed bearer tokens for stateless auth.
- **Role-Based Access Control (RBAC)**: Enforces role permissions (e.g., `user` can create, `admin` can delete).
- **Rate Limiting**: Sliding-window IP rate limiter preventing brute-force and DoS attacks.
- **Input Validation**: Strict schema checks, email validation, length constraints, and sanitization.

### Phase 5: Multi-Tier Caching
- **HTTP Caching**: Generates `ETag` and evaluates `If-None-Match` headers for instant `304 Not Modified` responses.
- **L1 Application Cache**: In-process thread-safe cache with automatic TTL expiration.
- **L2 Redis Cache**: Connects to Redis cluster/instance when available, with a thread-safe in-memory replica fallback.
- **Cache Invalidation**: Automatic eviction on mutations (`POST /api/users`, `DELETE /api/users/<id>`).

---

## ⚙️ Configuration & Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SERVER_HOST` | `127.0.0.1` | Binding host address |
| `SERVER_PORT` | `8080` | Port to listen on |
| `SERVER_WORKERS` | `10` | Worker threads in Thread Pool |
| `ENABLE_TLS` | `false` | Set to `true` / `1` to enable HTTPS |
| `JWT_SECRET` | `super-secret...` | Secret key for signing JWT tokens |
| `JWT_EXPIRATION_SECONDS` | `3600` | Expiration lifetime for JWTs |
| `REDIS_HOST` | `127.0.0.1` | Redis host |
| `REDIS_PORT` | `6379` | Redis port |
| `MYSQL_HOST` | `127.0.0.1` | MySQL server host |
| `MYSQL_PORT` | `3306` | MySQL server port |
| `MYSQL_USER` | `root` | MySQL user |
| `MYSQL_PASSWORD` | `""` | MySQL password |
| `MYSQL_DATABASE` | `network_prog_db` | MySQL database name |
| `DB_POOL_SIZE` | `5` | MySQL connection pool size |

---

## 🚀 Running the Server

### 1. Default Mode (Plain HTTP + SQLite Fallback)
```bash
python3 server.py
```

### 2. HTTPS / TLS Mode
```bash
ENABLE_TLS=true SERVER_PORT=8443 python3 server.py
```

### 3. Production Multi-Tier Mode (With MySQL, Redis, & TLS)
```bash
MYSQL_HOST=127.0.0.1 \
MYSQL_USER=root \
MYSQL_PASSWORD=secret \
REDIS_HOST=127.0.0.1 \
ENABLE_TLS=true \
python3 server.py
```

---

## 🧪 Testing with cURL & API Reference

### 1. Pre-seeded Test Accounts
- **Admin**: `admin@example.com` / `AdminPass123!` (Role: `admin`)
- **User**: `alice@example.com` / `AlicePass123!` (Role: `user`)

---

### 2. Authentication & JWT

**Login (Obtain JWT Token):**
```bash
curl -i -X POST http://127.0.0.1:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "AdminPass123!"}'
```

**Register New Account:**
```bash
curl -i -X POST http://127.0.0.1:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name": "Bob Vance", "email": "bob@example.com", "password": "BobPassword123!", "role": "user"}'
```

**Access Protected Profile:**
```bash
curl -i http://127.0.0.1:8080/api/auth/me \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>"
```

---

### 3. Multi-Tier Cached Users API

**Fetch Users (Observing Cache Tiers):**
```bash
curl -i http://127.0.0.1:8080/api/users
```
*Note the header `X-Cache-Lookup: L1_APP_CACHE` or `L2_REDIS_CACHE` on subsequent requests.*

**HTTP ETag / 304 Not Modified Test:**
```bash
# Pass the ETag received from the previous request
curl -i http://127.0.0.1:8080/api/users \
  -H 'If-None-Match: "your-etag-hash"'
```

**Create User (Requires Bearer Token):**
```bash
curl -i -X POST http://127.0.0.1:8080/api/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>" \
  -d '{"name": "Carol White", "email": "carol@example.com", "role": "user"}'
```

**Delete User (Requires Admin Role):**
```bash
curl -i -X DELETE http://127.0.0.1:8080/api/users/2 \
  -H "Authorization: Bearer <ADMIN_JWT_TOKEN>"
```

---

### 4. Cache Management & Metrics

**Get Real-Time Cache Telemetry:**
```bash
curl -i http://127.0.0.1:8080/api/cache/stats
```

**Flush Cache Tiers:**
```bash
curl -i -X POST http://127.0.0.1:8080/api/cache/flush
```

---

## 🖥️ Interactive Web Dashboard
Open **http://127.0.0.1:8080** in your browser to:
- Inspect live **L1 App Cache**, **L2 Redis Cache**, and **Database queries**.
- Switch roles (Guest, User, Admin) with instant one-click JWT authentication.
- Test RBAC deletion guards and sliding-window rate limiters.
- Run the 20-request concurrency stress test with live telemetry visualization.
