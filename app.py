from flask import Flask, request, redirect, session, render_template_string
import os, json, datetime
import bcrypt

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Load users
with open("users.json") as f:
    USERS = json.load(f)

# ---------- LOGGING FUNCTION ----------
def log_event(event):
    with open("logs.txt", "a") as f:
        f.write(f"{datetime.datetime.now()} | {request.remote_addr} | {event}\n")

# ---------- LOGIN PAGE ----------
login_page = """
<link rel="stylesheet" href="/static/style.css">
<div class="container">
<h2>NetTool Login</h2>
<form method="POST">
    <input name="username" placeholder="Username">
    <input name="password" type="password" placeholder="Password">
    <button>Login</button>
</form>
<p>{{msg}}</p>
</div>
"""

# ---------- DASHBOARD ----------
dashboard = """
<link rel="stylesheet" href="/static/style.css">
<div class="container">
<h2>Network Utility - Ping Tool</h2>
<form method="POST">
    <input name="ip" placeholder="Enter IP">
    <button>Ping</button>
</form>

<pre>{{output}}</pre>

<a href="/logout">Logout</a>
</div>
"""

# ---------- LOGIN ROUTE ----------
@app.route("/", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        user = request.form.get("username")
        pw = request.form.get("password")

        log_event(f"LOGIN_ATTEMPT user={user}")

        if user in USERS:
            stored_hash = USERS[user].encode()

            if bcrypt.checkpw(pw.encode(), stored_hash):
                session["user"] = user
                log_event(f"LOGIN_SUCCESS user={user}")
                return redirect("/dashboard")

        msg = "Invalid credentials"
        log_event(f"LOGIN_FAIL user={user}")

    return render_template_string(login_page, msg=msg)

# ---------- DASHBOARD ROUTE ----------
@app.route("/dashboard", methods=["GET", "POST"])
def dash():
    if "user" not in session:
        return redirect("/")

    output = ""

    if request.method == "POST":
        ip = request.form.get("ip")

        log_event(f"PING_REQUEST input={ip}")

        # 🔥 VULNERABILITY (COMMAND INJECTION)
        output = os.popen("ping -c 2 " + ip).read()

    return render_template_string(dashboard, output=output)

# ---------- LOGOUT ----------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ---------- RUN ----------
app.run(host="0.0.0.0", port=5000)
