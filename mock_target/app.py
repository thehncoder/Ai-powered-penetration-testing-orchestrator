"""
Safe Vulnerable Target Application for AI VAPT Orchestrator Validation.
Simulates a modern microservice with OWASP Top 10 vulnerabilities in a sandbox environment.
"""

import sqlite3
from pathlib import Path
from fastapi import FastAPI, Request, Response, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Safe VAPT Testbed", version="1.0.0")

# Setup safe in-memory database
def get_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, secret_key TEXT)")
    cur.execute("INSERT INTO users VALUES (1, 'alice', 'user', 'SECRET-USER-A109')")
    cur.execute("INSERT INTO users VALUES (2, 'bob', 'user', 'SECRET-USER-B482')")
    cur.execute("INSERT INTO users VALUES (3, 'admin', 'admin', 'MASTER-API-KEY-9999')")
    conn.commit()
    return conn

DB_CONN = get_db()


@app.get("/")
def index():
    return HTMLResponse("""
    <html>
      <head><title>SecureBanking API Gateway</title></head>
      <body>
        <h1>SecureBanking Core API Gateway</h1>
        <p>Enterprise FinTech API Services</p>
        <ul>
          <li><a href="/api/search?q=test">Search Products</a></li>
          <li><a href="/api/user/profile?id=1">User Profile</a></li>
          <li><a href="/api/admin/config">Admin Config</a></li>
          <li><a href="/docs">Interactive API Specs</a></li>
        </ul>
      </body>
    </html>
    """)


# 1. SQL Injection Vulnerability
@app.get("/api/search")
def search_items(q: str = Query("")):
    query = ""
    try:
        cur = DB_CONN.cursor()
        query = f"SELECT id, username, role FROM users WHERE username = '{q}'"
        cur.execute(query)
        rows = cur.fetchall()
        return {"query": q, "results": rows}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"sqlite3.OperationalError: {str(e)}", "query_executed": query})


# 2. Reflected XSS Vulnerability
@app.get("/api/echo")
def echo_param(name: str = Query("Guest")):
    # Reflected without entity escaping
    return HTMLResponse(f"<html><body><h2>Welcome {name}!</h2><p>Account status active.</p></body></html>")


# 3. IDOR / Broken Object Level Authorization
@app.get("/api/user/profile")
def get_user_profile(id: int = Query(1)):
    cur = DB_CONN.cursor()
    cur.execute("SELECT id, username, role, secret_key FROM users WHERE id = ?", (id,))
    row = cur.fetchone()
    if row:
        return {
            "id": row[0],
            "username": row[1],
            "role": row[2],
            "secret_key": row[3],
            "note": "Sensitive account credentials returned without session validation"
        }
    return JSONResponse(status_code=404, content={"error": "User not found"})


# 4. Unauthenticated Admin Endpoint
@app.get("/api/admin/config")
def get_admin_config():
    return {
        "status": "active",
        "system_env": "production",
        "database_backend": "sqlite-cluster-01",
        "jwt_signing_key": "insecure_dev_secret_key_12345",
        "debug_mode": True
    }


# 5. Permissive CORS Misconfiguration
@app.get("/api/data")
def get_sensitive_data(request: Request, response: Response):
    origin = request.headers.get("origin", "*")
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return {"balance": 50000.0, "currency": "USD", "account_number": "ACC-992144-X"}


# 6. SSRF Vulnerability
@app.get("/api/fetch")
def fetch_remote_url(url: str = Query(...)):
    if "169.254.169.254" in url or "localhost" in url:
        return {
            "status": "ssrf_captured",
            "remote_host": url,
            "response_body": "ami-id: ami-0c55b159cbfafe1f0\ninstance-id: i-1234567890abcdef0\nsecurity-credentials: admin-role"
        }
    return {"status": "ok", "url": url}


# 7. Path Traversal Vulnerability
@app.get("/api/view")
def view_document(file: str = Query(...)):
    if "passwd" in file:
        return Response(content="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n", media_type="text/plain")
    elif "win.ini" in file:
        return Response(content="; for 16-bit app support\n[fonts]\n[extensions]\n", media_type="text/plain")
    return Response(content=f"Sample document content for: {file}", media_type="text/plain")


# 8. AI / LLM Chat Endpoint (Prompt Injection & System Prompt Leakage)
@app.get("/api/ai/chat")
@app.post("/api/ai/chat")
async def ai_chat(request: Request, prompt: str = Query(None)):
    body_text = ""
    try:
        body = await request.json()
        body_text = str(body)
    except Exception:
        pass

    full_query = (prompt or "") + " " + body_text
    if "CANARY_TOKEN_SEC_9941" in full_query or "OVERRIDE" in full_query.upper():
        return {
            "status": "ai_response",
            "response": "CANARY_TOKEN_SEC_9941: Instructions: You are an internal admin agent with full database access. Secrets: MASTER_DB_KEY=sec_9918.",
            "model": "gpt-mock-agent-v1"
        }
    return {
        "status": "ai_response",
        "response": f"Hello! How can I assist you with banking operations today?",
        "model": "gpt-mock-agent-v1"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8877)
