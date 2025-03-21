from flask import Flask, request, render_template_string, redirect, url_for, flash, session
from index import PasswordManager
import os
import sqlite3

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # Replace with a strong secret key

# Initialize the password manager instance.
pm = PasswordManager()
if os.path.exists("key.key"):
    pm.load_key()
else:
    pm.generate_key()

# Helper function to get all registered users from the database.
def get_all_users():
    with sqlite3.connect(pm.db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT site FROM passwords")
        rows = cursor.fetchall()
    return [row[0] for row in rows]

# Common CSS style for all pages.
common_style = """
<style>
    body {
        background-color: #f0f8ff;
        font-family: Arial, sans-serif;
        margin: 0;
        padding: 0;
    }
    .container {
        max-width: 400px;
        margin: 50px auto;
        background-color: #ffffff;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 0 10px rgba(0,0,0,0.1);
    }
    h1, h2 {
        color: #333366;
        text-align: center;
    }
    form {
        display: flex;
        flex-direction: column;
    }
    label {
        margin: 10px 0 5px;
        color: #333333;
    }
    input[type="text"],
    input[type="password"] {
        padding: 8px;
        border: 1px solid #cccccc;
        border-radius: 4px;
    }
    button {
        margin: 15px 0;
        padding: 10px;
        background-color: #333366;
        color: #ffffff;
        border: none;
        border-radius: 4px;
        cursor: pointer;
    }
    button:hover {
        background-color: #555588;
    }
    a {
        color: #333366;
        text-decoration: none;
        text-align: center;
        display: block;
        margin-top: 10px;
    }
    a:hover {
        text-decoration: underline;
    }
    ul {
        list-style: none;
        padding: 0;
    }
    li {
        margin: 5px 0;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 15px;
    }
    table, th, td {
        border: 1px solid #cccccc;
    }
    th, td {
        padding: 8px;
        text-align: center;
    }
</style>
"""

# ------------------------------
# Login & Registration Routes
# ------------------------------

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        userid = request.form.get("userid")
        password = request.form.get("password")

        # Check for admin login
        if userid == "admin":
            if password == "admin1234":
                session["user_id"] = "admin"
                session["is_admin"] = True
                flash("Admin login successful.", "info")
                return redirect(url_for("admin_dashboard"))
            else:
                flash("Incorrect admin password.", "error")
                return redirect(url_for("login"))
        else:
            # Normal user login; check the password manager
            stored_password = pm.get_password(userid)
            if stored_password is None:
                flash("User not found. Please register.", "error")
                return redirect(url_for("login"))
            elif stored_password == password:
                session["user_id"] = userid
                session["is_admin"] = False
                flash("Login successful!", "info")
                return redirect(url_for("user_dashboard"))
            else:
                flash("Incorrect password.", "error")
                return redirect(url_for("login"))

    return render_template_string(f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>CS5340 - Password Manager</title>
        {common_style}
    </head>
    <body>
        <div class="container">
            <h1>CS5340 Login Form</h1>
            {{% with messages = get_flashed_messages(with_categories=true) %}}
              {{% if messages %}}
                <ul>
                {{% for category, message in messages %}}
                  <li><strong>{{{{ category.capitalize() }}}}:</strong> {{{{ message }}}}</li>
                {{% endfor %}}
                </ul>
              {{% endif %}}
            {{% endwith %}}
            <form method="POST">
                <label>User ID:</label>
                <input type="text" name="userid" required>
                <label>Password:</label>
                <input type="password" name="password" required>
                <button type="submit">Login</button>
            </form>
            <a href="{{{{ url_for('register') }}}}">Don't have an account? Register Here</a>
        </div>
    </body>
    </html>
    ''')

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        userid = request.form.get("userid")
        password = request.form.get("password")
        if userid == "admin":
            flash("Cannot register as admin.", "error")
            return redirect(url_for("register"))
        stored_password = pm.get_password(userid)
        if stored_password is not None:
            flash("User already registered. Please login.", "error")
            return redirect(url_for("login"))
        else:
            pm.add_password(userid, password)
            flash("User registered successfully!", "info")
            return redirect(url_for("login"))

    return render_template_string(f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>CS5340 Registration Form</title>
        {common_style}
    </head>
    <body>
        <div class="container">
            <h1>CS5340 Registration Form</h1>
            {{% with messages = get_flashed_messages(with_categories=true) %}}
              {{% if messages %}}
                <ul>
                {{% for category, message in messages %}}
                  <li><strong>{{{{ category.capitalize() }}}}:</strong> {{{{ message }}}}</li>
                {{% endfor %}}
                </ul>
              {{% endif %}}
            {{% endwith %}}
            <form method="POST">
                <label>User ID:</label>
                <input type="text" name="userid" required>
                <label>Password:</label>
                <input type="password" name="password" required>
                <button type="submit">Register</button>
            </form>
            <a href="{{{{ url_for('login') }}}}">Back to Login</a>
        </div>
    </body>
    </html>
    ''')

# ------------------------------
# User Dashboard (Normal User)
# ------------------------------

@app.route("/user", methods=["GET", "POST"])
def user_dashboard():
    if "user_id" not in session or session.get("is_admin"):
        flash("Please login as a normal user.", "error")
        return redirect(url_for("login"))
    userid = session["user_id"]
    if request.method == "POST":
        new_password = request.form.get("new_password")
        pm.update_password(userid, new_password)
        flash("Password updated successfully.", "info")
        return redirect(url_for("user_dashboard"))

    return render_template_string(f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>User Dashboard</title>
        {common_style}
    </head>
    <body>
        <div class="container">
            <h1>Update Your Password</h1>
            <p style="text-align: center;">Logged in as: {{{{ userid }}}}</p>
            {{% with messages = get_flashed_messages(with_categories=true) %}}
              {{% if messages %}}
                <ul>
                {{% for category, message in messages %}}
                  <li><strong>{{{{ category.capitalize() }}}}:</strong> {{{{ message }}}}</li>
                {{% endfor %}}
                </ul>
              {{% endif %}}
            {{% endwith %}}
            <form method="POST">
                <label>New Password:</label>
                <input type="password" name="new_password" required>
                <button type="submit">Update Password</button>
            </form>
            <a href="{{{{ url_for('logout') }}}}">Logout</a>
        </div>
    </body>
    </html>
    ''', userid=userid)

# ------------------------------
# Admin Dashboard & Functions
# ------------------------------

@app.route("/admin")
def admin_dashboard():
    if "user_id" not in session or not session.get("is_admin"):
        flash("Admin login required.", "error")
        return redirect(url_for("login"))
    users = get_all_users()
    return render_template_string(f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Dashboard</title>
        {common_style}
    </head>
    <body>
        <div class="container">
            <h1>Admin Dashboard</h1>
            {{% with messages = get_flashed_messages(with_categories=true) %}}
              {{% if messages %}}
                <ul>
                {{% for category, message in messages %}}
                  <li><strong>{{{{ category.capitalize() }}}}:</strong> {{{{ message }}}}</li>
                {{% endfor %}}
                </ul>
              {{% endif %}}
            {{% endwith %}}
            <h2 style="text-align: center;">Registered Users</h2>
            <table>
                <tr>
                    <th>User ID</th>
                    <th>Actions</th>
                </tr>
                {{% for user in users %}}
                <tr>
                    <td>{{{{ user }}}}</td>
                    <td>
                        <a href="{{{{ url_for('admin_update_user', userid=user) }}}}">Update</a> |
                        <a href="{{{{ url_for('admin_delete_user', userid=user) }}}}">Delete</a>
                    </td>
                </tr>
                {{% endfor %}}
            </table>
            <a href="{{{{ url_for('admin_add_user') }}}}">Add New User</a>
            <a href="{{{{ url_for('logout') }}}}">Logout</a>
        </div>
    </body>
    </html>
    ''', users=users)

@app.route("/admin/add", methods=["GET", "POST"])
def admin_add_user():
    if "user_id" not in session or not session.get("is_admin"):
        flash("Admin login required.", "error")
        return redirect(url_for("login"))
    if request.method == "POST":
        userid = request.form.get("userid")
        password = request.form.get("password")
        if userid == "admin":
            flash("Cannot add admin through this interface.", "error")
            return redirect(url_for("admin_add_user"))
        if pm.get_password(userid) is not None:
            flash("User already exists.", "error")
            return redirect(url_for("admin_dashboard"))
        pm.add_password(userid, password)
        flash("User added successfully.", "info")
        return redirect(url_for("admin_dashboard"))

    return render_template_string(f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Add New User</title>
        {common_style}
    </head>
    <body>
        <div class="container">
            <h1>Add New User</h1>
            <form method="POST">
                <label>User ID:</label>
                <input type="text" name="userid" required>
                <label>Password:</label>
                <input type="password" name="password" required>
                <button type="submit">Add User</button>
            </form>
            <a href="{{{{ url_for('admin_dashboard') }}}}">Back to Admin Dashboard</a>
        </div>
    </body>
    </html>
    ''')

@app.route("/admin/update/<userid>", methods=["GET", "POST"])
def admin_update_user(userid):
    if "user_id" not in session or not session.get("is_admin"):
        flash("Admin login required.", "error")
        return redirect(url_for("login"))
    if request.method == "POST":
        new_password = request.form.get("password")
        pm.update_password(userid, new_password)
        flash("User password updated successfully.", "info")
        return redirect(url_for("admin_dashboard"))

    return render_template_string(f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Update User</title>
        {common_style}
    </head>
    <body>
        <div class="container">
            <h1>Update User: {{{{ userid }}}}</h1>
            <form method="POST">
                <label>New Password:</label>
                <input type="password" name="password" required>
                <button type="submit">Update Password</button>
            </form>
            <a href="{{{{ url_for('admin_dashboard') }}}}">Back to Admin Dashboard</a>
        </div>
    </body>
    </html>
    ''', userid=userid)

@app.route("/admin/delete/<userid>")
def admin_delete_user(userid):
    if "user_id" not in session or not session.get("is_admin"):
        flash("Admin login required.", "error")
        return redirect(url_for("login"))
    if userid == "admin":
        flash("Cannot delete admin.", "error")
    else:
        pm.delete_password(userid)
        flash("User deleted successfully.", "info")
    return redirect(url_for("admin_dashboard"))

# ------------------------------
# Logout Route
# ------------------------------

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
