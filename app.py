# ============================================================
# app.py — GradeVault Backend (Updated with Login System)
# ============================================================

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
# session → stores logged in user info between requests (like a cookie)
# redirect → sends the user to a different page
# url_for  → generates URLs by function name

from werkzeug.security import generate_password_hash, check_password_hash
# generate_password_hash → encrypts a password before saving to database
# check_password_hash    → checks if entered password matches the encrypted one

import sqlite3
import re  # used for email format validation
import os

app = Flask(__name__)

# Secret key is required for sessions to work securely
# In production this should be a long random string
app.secret_key = "gradevault_secret_key_2024"

DB_PATH = "grades.db"


# ============================================================
# DATABASE HELPERS
# ============================================================

def get_db():
    """Opens a connection to the database."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # prevents database locked errors
    return conn


def init_db():
    """Creates all tables if they don't exist."""
    conn = get_db()
    cursor = conn.cursor()

    # Users table — stores all accounts (admin, teacher, student)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,          -- stored as encrypted hash, never plain text
            role TEXT NOT NULL DEFAULT 'student', -- 'admin', 'teacher', or 'student'
            subject TEXT,                    -- only for teachers e.g. "Mathematics"
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Students table — links to a user account
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,                 -- links to users table (if student has account)
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Grades table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS grades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            grade REAL NOT NULL,
            max_grade REAL DEFAULT 100,
            teacher_id INTEGER,              -- which teacher recorded this grade
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
            FOREIGN KEY (teacher_id) REFERENCES users(id)
        )
    """)

    conn.commit()

    # Create a default admin account if none exists
    # Username: admin | Password: admin123
    existing_admin = conn.execute("SELECT id FROM users WHERE role = 'admin'").fetchone()
    if not existing_admin:
        conn.execute("""
            INSERT INTO users (fullname, username, email, password, role)
            VALUES (?, ?, ?, ?, ?)
        """, (
            "Administrator",
            "admin",
            "admin@gradevault.com",
            generate_password_hash("admin123"),  # password is encrypted
            "admin"
        ))
        conn.commit()
        print("Default admin created → username: admin | password: admin123")

    conn.close()


# ============================================================
# HELPER — check if user is logged in
# ============================================================

def get_current_user():
    """Returns the logged in user from the session, or None."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user


def login_required(role=None):
    """Check if user is logged in and has the right role."""
    user = get_current_user()
    if not user:
        return False
    if role and user["role"] != role:
        return False
    return True


# ============================================================
# PAGE ROUTES — serve HTML pages
# ============================================================

@app.route("/")
def home():
    # If already logged in, redirect to the right dashboard
    user = get_current_user()
    if user:
        return redirect(url_for(user["role"] + "_dashboard"))
    return redirect(url_for("login_page"))


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/register")
def register_page():
    return render_template("register.html")


@app.route("/dashboard/admin")
def admin_dashboard():
    # Only admin can see this page
    user = get_current_user()
    if not user or user["role"] != "admin":
        return redirect(url_for("login_page"))
    return render_template("dashboard_admin.html", user=dict(user))


@app.route("/dashboard/teacher")
def teacher_dashboard():
    # Only teachers can see this page
    user = get_current_user()
    if not user or user["role"] != "teacher":
        return redirect(url_for("login_page"))
    return render_template("dashboard_teacher.html", user=dict(user))


@app.route("/dashboard/student")
def student_dashboard():
    # Only students can see this page
    user = get_current_user()
    if not user or user["role"] != "student":
        return redirect(url_for("login_page"))
    return render_template("dashboard_student.html", user=dict(user))


# ============================================================
# AUTH API ENDPOINTS
# ============================================================

@app.route("/api/login", methods=["POST"])
def api_login():
    """Handles login — checks username and password."""
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Please enter both username and password"}), 400

    # Find the user by username
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    # Check if user exists and password is correct
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid username or password"}), 401

    # Save user info in session (this keeps them logged in)
    session["user_id"] = user["id"]
    session["role"]    = user["role"]

    # Send back which dashboard to redirect to
    redirects = {
        "admin":   "/dashboard/admin",
        "teacher": "/dashboard/teacher",
        "student": "/dashboard/student"
    }

    return jsonify({
        "message":  "Login successful",
        "role":     user["role"],
        "fullname": user["fullname"],
        "redirect": redirects[user["role"]]
    })


@app.route("/api/register", methods=["POST"])
def api_register():
    """Handles student self-registration."""
    data = request.get_json()
    fullname = data.get("fullname", "").strip()
    username = data.get("username", "").strip()
    email    = data.get("email", "").strip()
    password = data.get("password", "")

    # Validate all fields
    if not fullname or not username or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    # Validate email format on the server side too
    email_regex = r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
    if not re.match(email_regex, email):
        return jsonify({"error": "Please enter a valid email address"}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    try:
        conn = get_db()
        # Save the new student user with encrypted password
        conn.execute("""
            INSERT INTO users (fullname, username, email, password, role)
            VALUES (?, ?, ?, ?, 'student')
        """, (fullname, username, email, generate_password_hash(password)))

        # Also add them to the students table
        conn.execute("""
            INSERT INTO students (name, email)
            VALUES (?, ?)
        """, (fullname, email))

        conn.commit()
        conn.close()
        return jsonify({"message": "Account created successfully"}), 201

    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 409


@app.route("/api/logout", methods=["POST"])
def api_logout():
    """Logs the user out by clearing the session."""
    session.clear()
    return jsonify({"message": "Logged out"})


@app.route("/api/change-password", methods=["POST"])
def change_password():
    """Allows a logged in student to change their password."""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 403

    data             = request.get_json()
    current_password = data.get("current_password", "")
    new_password     = data.get("new_password", "")

    # Validate fields are not empty
    if not current_password or not new_password:
        return jsonify({"error": "All fields are required"}), 400

    # Check new password is long enough
    if len(new_password) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400

    # Verify the current password is correct
    if not check_password_hash(user["password"], current_password):
        return jsonify({"error": "Current password is incorrect"}), 401

    # Check new password is different from current
    if check_password_hash(user["password"], new_password):
        return jsonify({"error": "New password must be different from current password"}), 400

    # Save the new encrypted password
    conn = get_db()
    conn.execute(
        "UPDATE users SET password = ? WHERE id = ?",
        (generate_password_hash(new_password), user["id"])
    )
    conn.commit()
    conn.close()

    return jsonify({"message": "Password updated successfully"})


# ============================================================
# ADMIN API ENDPOINTS
# ============================================================

@app.route("/api/admin/teachers", methods=["GET"])
def get_teachers():
    """Get all teachers — admin only."""
    user = get_current_user()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    teachers = conn.execute(
        "SELECT id, fullname, username, email, subject FROM users WHERE role = 'teacher'"
    ).fetchall()
    conn.close()
    return jsonify([dict(t) for t in teachers])


@app.route("/api/admin/teachers", methods=["POST"])
def add_teacher():
    """Add a new teacher account — admin only."""
    user = get_current_user()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data     = request.get_json()
    fullname = data.get("fullname", "").strip()
    username = data.get("username", "").strip()
    email    = data.get("email", "").strip()
    password = data.get("password", "").strip()
    subject  = data.get("subject", "").strip()

    if not fullname or not username or not email or not password or not subject:
        return jsonify({"error": "All fields are required"}), 400

    # Validate email format
    email_regex = r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
    if not re.match(email_regex, email):
        return jsonify({"error": "Please enter a valid email address"}), 400

    try:
        conn = get_db()
        conn.execute("""
            INSERT INTO users (fullname, username, email, password, role, subject)
            VALUES (?, ?, ?, ?, 'teacher', ?)
        """, (fullname, username, email, generate_password_hash(password), subject))
        conn.commit()
        conn.close()
        return jsonify({"message": "Teacher added"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 409


@app.route("/api/admin/teachers/<int:teacher_id>", methods=["DELETE"])
def delete_teacher(teacher_id):
    """Delete a teacher account — admin only."""
    user = get_current_user()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ? AND role = 'teacher'", (teacher_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Teacher deleted"})


@app.route("/api/admin/stats", methods=["GET"])
def admin_stats():
    """Get overall system stats — admin only."""
    user = get_current_user()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    total_students = conn.execute("SELECT COUNT(*) as c FROM students").fetchone()["c"]
    total_teachers = conn.execute("SELECT COUNT(*) as c FROM users WHERE role='teacher'").fetchone()["c"]
    total_grades   = conn.execute("SELECT COUNT(*) as c FROM grades").fetchone()["c"]
    grades_data    = conn.execute("SELECT grade FROM grades").fetchall()
    grades         = [g["grade"] for g in grades_data]
    overall_avg    = round(sum(grades) / len(grades), 2) if grades else 0
    conn.close()

    return jsonify({
        "total_students": total_students,
        "total_teachers": total_teachers,
        "total_grades":   total_grades,
        "overall_average": overall_avg
    })


# ============================================================
# USERS API ENDPOINTS (admin only)
# ============================================================

@app.route("/api/admin/users", methods=["GET"])
def get_all_users():
    """Get all users in the system — admin only."""
    user = get_current_user()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    users = conn.execute("""
        SELECT id, fullname, username, email, role, subject, created_at
        FROM users ORDER BY created_at DESC
    """).fetchall()
    conn.close()

    return jsonify([dict(u) for u in users])


@app.route("/api/admin/users/<int:user_id>/reset-password", methods=["POST"])
def reset_user_password(user_id):
    """Reset a user's password back to their username — admin only."""
    admin = get_current_user()
    if not admin or admin["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    # Get the user we want to reset
    target_user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not target_user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    # New password = their username
    new_password = generate_password_hash(target_user["username"])
    conn.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, user_id))
    conn.commit()
    conn.close()

    return jsonify({
        "message": f"Password reset to username: {target_user['username']}"
    })


# ============================================================
# STUDENT & GRADE API ENDPOINTS (used by teacher dashboard)
# ============================================================

@app.route("/api/students", methods=["GET"])
def get_students():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()

    # Teachers see ALL students (so newly added students appear immediately)
    # Grades are then filtered by the teacher's subject below
    students = conn.execute("SELECT * FROM students ORDER BY name").fetchall()

    result = []
    for s in students:
        if user["role"] == "teacher":
            grades = conn.execute(
                "SELECT * FROM grades WHERE student_id = ? AND subject = ?",
                (s["id"], user["subject"])
            ).fetchall()
        else:
            grades = conn.execute(
                "SELECT * FROM grades WHERE student_id = ?", (s["id"],)
            ).fetchall()

        grade_list = [dict(g) for g in grades]
        avg = round(sum(g["grade"] for g in grade_list) / len(grade_list), 2) if grade_list else None
        status = "Pass" if avg and avg >= 50 else ("Fail" if avg is not None else "No Grades")

        result.append({
            "id": s["id"], "name": s["name"], "email": s["email"],
            "grades": grade_list, "average": avg, "status": status
        })

    conn.close()
    return jsonify(result)


@app.route("/api/students", methods=["POST"])
def add_student():
    user = get_current_user()
    if not user or user["role"] not in ["admin", "teacher"]:
        return jsonify({"error": "Unauthorized"}), 403

    data  = request.get_json()
    name  = data.get("name", "").strip()
    email = data.get("email", "").strip()

    if not name or not email:
        return jsonify({"error": "Name and email are required"}), 400

    # Auto-generate username and password from the part before @ in email
    # e.g. jane@school.ac.ke → username: jane, password: jane
    username = email.split("@")[0]
    default_password = generate_password_hash(username)

    try:
        conn = get_db()

        # Check if a user account already exists for this email
        existing_user = conn.execute(
            "SELECT id FROM users WHERE email = ? OR username = ?", (email, username)
        ).fetchone()

        if not existing_user:
            # Auto-create a login account for this student
            conn.execute("""
                INSERT INTO users (fullname, username, email, password, role)
                VALUES (?, ?, ?, ?, 'student')
            """, (name, username, email, default_password))

        # Add student to the students table
        conn.execute("INSERT INTO students (name, email) VALUES (?, ?)", (name, email))
        conn.commit()

        student = conn.execute("SELECT * FROM students WHERE email = ?", (email,)).fetchone()
        conn.close()

        return jsonify({
            "message": "Student added",
            "student": dict(student),
            "login_info": {
                "username": username,
                "password": username  # default password equals the username
            }
        }), 201

    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already exists"}), 409


@app.route("/api/students/<int:student_id>", methods=["DELETE"])
def delete_student(student_id):
    user = get_current_user()
    if not user or user["role"] not in ["admin", "teacher"]:
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    conn.execute("DELETE FROM grades WHERE student_id = ?", (student_id,))
    conn.execute("DELETE FROM students WHERE id = ?", (student_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Student deleted"})


@app.route("/api/grades", methods=["POST"])
def add_grade():
    user = get_current_user()
    if not user or user["role"] not in ["admin", "teacher"]:
        return jsonify({"error": "Unauthorized"}), 403

    data       = request.get_json()
    student_id = data.get("student_id")
    subject    = data.get("subject", "").strip()
    grade      = data.get("grade")
    max_grade  = data.get("max_grade", 100)

    if not student_id or not subject or grade is None:
        return jsonify({"error": "student_id, subject, and grade are required"}), 400

    if not (0 <= float(grade) <= float(max_grade)):
        return jsonify({"error": "Grade must be between 0 and max_grade"}), 400

    conn = get_db()
    conn.execute(
        "INSERT INTO grades (student_id, subject, grade, max_grade, teacher_id) VALUES (?, ?, ?, ?, ?)",
        (student_id, subject, grade, max_grade, user["id"])
    )
    conn.commit()
    conn.close()
    return jsonify({"message": "Grade added"}), 201


@app.route("/api/grades/<int:grade_id>", methods=["DELETE"])
def delete_grade(grade_id):
    user = get_current_user()
    if not user or user["role"] not in ["admin", "teacher"]:
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    conn.execute("DELETE FROM grades WHERE id = ?", (grade_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Grade deleted"})


@app.route("/api/stats", methods=["GET"])
def get_stats():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    total_students = conn.execute("SELECT COUNT(*) as c FROM students").fetchone()["c"]
    grades_data    = conn.execute("SELECT grade FROM grades").fetchall()
    grades         = [g["grade"] for g in grades_data]
    overall_avg    = round(sum(grades) / len(grades), 2) if grades else 0
    passing        = conn.execute("""
        SELECT COUNT(*) as c FROM (
            SELECT student_id, AVG(grade) as avg FROM grades
            GROUP BY student_id HAVING avg >= 50
        )
    """).fetchone()["c"]
    conn.close()

    return jsonify({
        "total_students":  total_students,
        "overall_average": overall_avg,
        "passing_students": passing,
        "failing_students": total_students - passing
    })


# Student viewing their own grades
@app.route("/api/my-grades", methods=["GET"])
def my_grades():
    """Student sees only their own grades."""
    user = get_current_user()
    if not user or user["role"] != "student":
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    # Find the student record linked to this user's email
    student = conn.execute(
        "SELECT * FROM students WHERE email = ?", (user["email"],)
    ).fetchone()

    if not student:
        conn.close()
        return jsonify({"grades": [], "average": None, "status": "No Grades"})

    grades = conn.execute(
        "SELECT * FROM grades WHERE student_id = ?", (student["id"],)
    ).fetchall()

    grade_list = [dict(g) for g in grades]
    avg = round(sum(g["grade"] for g in grade_list) / len(grade_list), 2) if grade_list else None
    status = "Pass" if avg and avg >= 50 else ("Fail" if avg is not None else "No Grades")

    conn.close()
    return jsonify({
        "student": dict(student),
        "grades":  grade_list,
        "average": avg,
        "status":  status
    })


# ============================================================
# START
# ============================================================
@app.route("/reset-admin")
def reset_admin():
    conn = get_db()
    conn.execute("DELETE FROM users WHERE username = 'admin'")
    conn.execute("""
        INSERT INTO users (fullname, username, email, password, role)
        VALUES (?, ?, ?, ?, ?)
    """, ("Administrator", "admin", "admin@gradevault.com",
          generate_password_hash("admin123"), "admin"))
    conn.commit()
    conn.close()
    return "Admin reset! Login with admin / admin123"
    
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
