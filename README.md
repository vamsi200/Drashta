# Drashta

**Drashta** (meaning *“The Seer”*) is a Linux security tool that monitors and streams real-time, security-relevant events from your machine.

It parses **journald logs** using **regex patterns** across critical system services such as:

- **SSHD**
- **SUDO**
- **KERNEL**
- **NetworkManager**
- **Firewalld**
- **Cron**
- **User Sessions**

It converts these raw logs into structured events and streams them to a web UI using **Server-Sent Events (SSE)** for real-time visualization.

# Features

### Backend (Rust + Axum)
- Axum-based HTTP server  
- Real-time event broadcast via `GET /live` (SSE)
- Fully structured JSON API
- Uses **tokio** + broadcast channels for live updates
- Modular event parsers for each system service

### Frontend (React + Vite + TailwindCSS)
- Reactive real-time UI
- Live security event stream
- TailwindCSS-based minimal interface

---

# Setup

```bash
git clone https://github.com/vamsi200/Drashta
cd Drashta/
chmod +x build.sh
./build.sh

```

After the server starts, we could access the UI `https://localhost:3200/app/`
> Note: The server would be started with the default port: `3200`, you could change this with `--port` option.

> ./target/release/drashta --port 1234 

 
# API ENDPOINTS
```bash
GET /live
  Streams real-time events via SSE.

GET /drain
  Returns the most recent events.

GET /older?event_name=<name>&cursor=<cursor>&limit=<n>
  Fetches logs newer than the given cursor.

GET /previous?event_name=<name>&cursor=<cursor>&limit=<n>
  Fetches logs older than the given cursor.

```

# LICENSE
This project is open source and available under the MIT License.
