# Network Programming HTTP Server

A complete end-to-end multi-tier network server built from scratch with Python sockets, implementing:
1. **Phase 1: Low-Level Socket HTTP Server** (TCP sockets & HTTP/1.1 parser/builder)
2. **Phase 2: Application & Database Layer** (MySQL with connection pooling & fallback)
3. **Phase 3: Thread Pool Concurrency** (Controlled multi-worker concurrency)

---

## 🏗️ Architecture

```
Client Browser / cURL
       │ (TCP Connection)
       ▼
┌──────────────────────────────────────────────┐
│  Phase 1: Low-Level Socket Listener (server.py)│
│  - socket.bind() & socket.listen()           │
│  - HTTP/1.1 Request/Response Parser          │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│  Phase 3: Thread Pool Concurrency            │
│  - ThreadPoolExecutor(max_workers=10)        │
│  - Bounded worker queue                      │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│  Phase 2: Application Router & DB Layer      │
│  - REST API Routing (GET, POST, DELETE)      │
│  - Static File Server with traversal check   │
│  - MySQL Connection Pool (db.py)             │
│  - SQLite Fallback Mode                      │
└──────────────────────────────────────────────┘
```

---

## ⚙️ Configuration & Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SERVER_WORKERS` | `10` | Number of worker threads in the Thread Pool |
| `MYSQL_HOST` | `127.0.0.1` | MySQL server host |
| `MYSQL_PORT` | `3306` | MySQL server port |
| `MYSQL_USER` | `root` | MySQL user |
| `MYSQL_PASSWORD` | `""` | MySQL password |
| `MYSQL_DATABASE` | `network_prog_db` | MySQL database name |
| `DB_POOL_SIZE` | `5` | Size of the MySQL connection pool |

> **Note**: If MySQL is not running or unreachable, the server seamlessly falls back to an embedded SQLite database (`app.db`) without crashing.

---

## 🚀 Running the Server

Start the server:
```bash
python3 server.py
```

With custom MySQL credentials:
```bash
MYSQL_USER=myuser MYSQL_PASSWORD=mypass python3 server.py
```

With custom thread pool size:
```bash
SERVER_WORKERS=25 python3 server.py
```

---

## 🧪 Testing & Verification

### 1. Interactive UI
Open [http://127.0.0.1:8080](http://127.0.0.1:8080) in your browser to:
- Inspect live thread pool metrics.
- Perform user CRUD operations directly on the database.
- Run the 20-request concurrency stress test.

### 2. cURL Commands

**Get Server & Thread Pool Info:**
```bash
curl -i http://127.0.0.1:8080/api/info
```

**Create User (Application -> MySQL):**
```bash
curl -i -X POST http://127.0.0.1:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{"name": "Alice Smith", "email": "alice@example.com"}'
```

**List Users:**
```bash
curl -i http://127.0.0.1:8080/api/users
```

**Delete User:**
```bash
curl -i -X DELETE http://127.0.0.1:8080/api/users/1
```
