from flask import Flask, request, redirect, session, render_template_string
import os

app = Flask(__name__)
app.secret_key = "secretkey"

# Hardcoded credentials
USERNAME = "admin"
PASSWORD = "password123"

login_page = """
<h2>NetTool Login</h2>
<form method="POST">
    Username: <input name="username"><br>
    Password: <input name="password" type="password"><br>
    <input type="submit" value="Login">
</form>
<p>{{msg}}</p>
"""

dashboard = """
<h2>Network Utility - Ping Tool</h2>
<form method="POST">
    Enter IP: <input name="ip">
    <input type="submit" value="Ping">
</form>

<pre>{{output}}</pre>

<a href="/logout">Logout</a>
"""

@app.route("/", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        user = request.form.get("username")
        pw = request.form.get("password")

        if user == USERNAME and pw == PASSWORD:
            session["user"] = user
            return redirect("/dashboard")
        else:
            msg = "Invalid credentials"

    return render_template_string(login_page, msg=msg)

@app.route("/dashboard", methods=["GET", "POST"])
def dash():
    if "user" not in session:
        return redirect("/")

    output = ""
    if request.method == "POST":
        ip = request.form.get("ip")

        # VULNERABILITY (command injection)
        output = os.popen("ping -c 2 " + ip).read()

    return render_template_string(dashboard, output=output)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

app.run(host="0.0.0.0", port=5000)
