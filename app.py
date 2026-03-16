# ============================================================
# app.py — GradeVault Backend (PostgreSQL version)
# ============================================================

import sys
import logging
# Force unbuffered output so logs appear in Render immediately
logging.basicConfig(level=logging.INFO, stream=sys.stderr, force=True)

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import psycopg2.extras
import re
import os
import secrets
import requests
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "gradevault_secret_key_2024"

# Session survives refresh but expires after 8 hours of inactivity
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True

@app.route("/test-email")
def test_email():
    try:
        send_reset_email("fidelclinton4@gmail.com", "testtoken123")
        return "EMAIL SENT OK"
    except Exception as e:
        return f"EMAIL FAILED: {type(e).__name__}: {e}"

# ============================================================
# EMAIL CONFIG (Gmail SMTP)
# ============================================================
BREVO_API_KEY = os.environ.get("BREVO_API_KEY")
MAIL_FROM     = os.environ.get("MAIL_FROM", "fidelclinton4@gmail.com")
MAIL_FROM_NAME = os.environ.get("MAIL_FROM_NAME", "GradeVault")
APP_BASE_URL  = os.environ.get("APP_BASE_URL", "https://grade-tracker-pq0y.onrender.com")

def send_reset_email(to_email, token):
    """Send password reset email via Brevo HTTP API."""
    reset_link = f"{APP_BASE_URL}/reset-password?token={token}"

    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;background:#0f1117;color:#f0f0f0;border-radius:12px;padding:2rem">
      <h2 style="color:#f5c518;margin-bottom:0.5rem">Password Reset</h2>
      <p style="color:#aaa;margin-bottom:1.5rem">You requested a password reset for your GradeVault account.</p>
      <a href="{reset_link}" style="display:inline-block;background:#f5c518;color:#0f1117;font-weight:700;padding:12px 28px;border-radius:8px;text-decoration:none;font-size:1rem">Reset My Password</a>
      <p style="color:#666;font-size:0.8rem;margin-top:1.5rem">This link expires in <strong style="color:#aaa">30 minutes</strong>. If you didn't request this, ignore this email.</p>
      <p style="color:#888;font-size:0.75rem;margin-top:0.5rem">Or copy this link: {reset_link}</p>
      <p style="color:#444;font-size:0.75rem;margin-top:1rem">— GradeVault System</p>
    </div>
    """

    logging.info(f"[EMAIL DEBUG] Attempting to send to: {to_email}")
    logging.info(f"[EMAIL DEBUG] Reset link: {reset_link}")
    logging.info(f"[EMAIL DEBUG] BREVO_API_KEY set: {'yes' if BREVO_API_KEY else 'NO - EMPTY!'}")

    payload = {
        "sender": {"name": MAIL_FROM_NAME, "email": MAIL_FROM},
        "to": [{"email": to_email}],
        "subject": "GradeVault — Password Reset Request",
        "htmlContent": html,
        "textContent": f"Reset your GradeVault password: {reset_link}\n\nExpires in 30 minutes."
    }

    response = requests.post(
        "https://api.brevo.com/v3/smtp/email",
        headers={
            "accept": "application/json",
            "api-key": BREVO_API_KEY,
            "content-type": "application/json"
        },
        json=payload,
        timeout=20
    )

    logging.info(f"[EMAIL DEBUG] Brevo response: {response.status_code} {response.text}")

    if response.status_code not in (200, 201):
        raise Exception(f"Brevo API error {response.status_code}: {response.text}")

    logging.info(f"[EMAIL DEBUG] Email sent successfully to {to_email}")

# ============================================================
# DATABASE HELPERS
# ============================================================

def get_db():
    """Opens a connection to the PostgreSQL database."""
    conn = psycopg2.connect(
        os.environ.get("DATABASE_URL"),
        cursor_factory=psycopg2.extras.RealDictCursor  # returns rows as dicts like sqlite
    )
    return conn


def init_db():
    """Creates all tables if they don't exist."""
    conn = get_db()
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            fullname TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            subject TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Students table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Grades table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS grades (
            id SERIAL PRIMARY KEY,
            student_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            grade REAL NOT NULL,
            max_grade REAL DEFAULT 100,
            comment TEXT,
            teacher_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
            FOREIGN KEY (teacher_id) REFERENCES users(id)
        )
    """)

    # Add comment column if it doesn't exist (for existing databases)
    cursor.execute("""
        ALTER TABLE grades ADD COLUMN IF NOT EXISTS comment TEXT
    """)

    # Password reset tokens table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()

    # Create default admin if none exists
    cursor.execute("SELECT id FROM users WHERE role = 'admin'")
    existing_admin = cursor.fetchone()
    if not existing_admin:
        cursor.execute("""
            INSERT INTO users (fullname, username, email, password, role)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            "Administrator",
            "admin",
            "admin@gradevault.com",
            generate_password_hash("admin123"),
            "admin"
        ))
        conn.commit()
        print("Default admin created → username: admin | password: admin123")

    cursor.close()
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
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user


# ============================================================
# CBC GRADING HELPER
# ============================================================

# CBC subjects preset list
# Kenya CBC Junior Secondary School (Grade 7–9) subjects
CBC_SUBJECTS = [
    "English",
    "Kiswahili",
    "Mathematics",
    "Integrated Science",
    "Social Studies",
    "Religious Education (CRE)",
    "Religious Education (IRE)",
    "Religious Education (HRE)",
    "Pre-Technical Studies",
    "Business Studies",
    "Computer Studies",
    "Agriculture",
    "Nutrition & Home Science",
    "Creative Arts & Sports"
]

def cbc_status(average):
    """Return CBC performance level based on percentage average."""
    if average is None:
        return "No Grades"
    if average >= 75:
        return "EE"   # Exceeds Expectation
    elif average >= 50:
        return "ME"   # Meets Expectation
    elif average >= 25:
        return "AE"   # Approaches Expectation
    else:
        return "BE"   # Below Expectation


# ============================================================
# PAGE ROUTES
# ============================================================

@app.route("/")
def home():
    user = get_current_user()
    if user:
        return redirect(url_for(user["role"] + "_dashboard"))
    return redirect(url_for("login_page"))


# ============================================================
# PASSWORD RESET ROUTES
# ============================================================

@app.route("/forgot-password")
def forgot_password_page():
    return render_template("forgot_password.html")

@app.route("/reset-password")
def reset_password_page():
    token = request.args.get("token", "")
    return render_template("reset_password.html", token=token)

@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    data  = request.get_json()
    email = data.get("email", "").strip().lower()
    logging.info(f"[RESET] Forgot password request for: {email}")
    if not email:
        return jsonify({"error": "Email is required"}), 400

    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, fullname, email FROM users WHERE LOWER(email) = %s", (email,))
    user = cursor.fetchone()

    if not user:
        logging.info(f"[RESET] No user found for email: {email}")
        cursor.close(); conn.close()
        return jsonify({"message": "If that email exists, a reset link has been sent."})

    logging.info(f"[RESET] User found: {user['fullname']} ({user['email']})")

    # Generate secure token, expires in 30 minutes
    token      = secrets.token_urlsafe(48)
    expires_at = datetime.utcnow() + timedelta(minutes=30)

    # Invalidate any existing tokens for this user
    cursor.execute("UPDATE password_reset_tokens SET used = TRUE WHERE user_id = %s AND used = FALSE", (user["id"],))
    cursor.execute(
        "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (%s, %s, %s)",
        (user["id"], token, expires_at)
    )
    conn.commit()
    cursor.close(); conn.close()

    logging.info(f"[RESET] Token generated, attempting to send email to {user['email']}")
    try:
        send_reset_email(user["email"], token)
        logging.info(f"[RESET] Email sent successfully to {user['email']}")
    except Exception as e:
        logging.error(f"[EMAIL ERROR] {type(e).__name__}: {e}")
        return jsonify({"error": f"Email failed: {str(e)}"}), 500

    return jsonify({"message": "If that email exists, a reset link has been sent."})


@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    data     = request.get_json()
    token    = data.get("token", "").strip()
    password = data.get("password", "")

    if not token or not password:
        return jsonify({"error": "Token and password are required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT t.id, t.user_id, t.expires_at, t.used
        FROM password_reset_tokens t
        WHERE t.token = %s
    """, (token,))
    record = cursor.fetchone()

    if not record:
        cursor.close(); conn.close()
        return jsonify({"error": "Invalid or expired reset link."}), 400
    if record["used"]:
        cursor.close(); conn.close()
        return jsonify({"error": "This reset link has already been used."}), 400
    if datetime.utcnow() > record["expires_at"]:
        cursor.close(); conn.close()
        return jsonify({"error": "This reset link has expired. Please request a new one."}), 400

    # Update password and mark token as used
    cursor.execute(
        "UPDATE users SET password = %s WHERE id = %s",
        (generate_password_hash(password), record["user_id"])
    )
    cursor.execute("UPDATE password_reset_tokens SET used = TRUE WHERE id = %s", (record["id"],))
    conn.commit()
    cursor.close(); conn.close()

    return jsonify({"message": "Password reset successfully! You can now log in."})


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/register")
def register_page():
    return render_template("register.html")


@app.route("/dashboard/admin")
def admin_dashboard():
    user = get_current_user()
    if not user or user["role"] != "admin":
        return redirect(url_for("login_page"))
    return render_template("dashboard_admin.html", user=dict(user))


@app.route("/dashboard/teacher")
def teacher_dashboard():
    user = get_current_user()
    if not user or user["role"] != "teacher":
        return redirect(url_for("login_page"))
    return render_template("dashboard_teacher.html", user=dict(user))


@app.route("/dashboard/student")
def student_dashboard():
    user = get_current_user()
    if not user or user["role"] != "student":
        return redirect(url_for("login_page"))
    return render_template("dashboard_student.html", user=dict(user))


# ============================================================
# AUTH API ENDPOINTS
# ============================================================

@app.route("/api/login", methods=["POST"])
def api_login():
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Please enter both username and password"}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid username or password"}), 401

    session.permanent = True
    session["user_id"] = user["id"]
    session["role"]    = user["role"]

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
    data     = request.get_json()
    fullname = data.get("fullname", "").strip()
    username = data.get("username", "").strip()
    email    = data.get("email", "").strip()
    password = data.get("password", "")

    if not fullname or not username or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    email_regex = r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
    if not re.match(email_regex, email):
        return jsonify({"error": "Please enter a valid email address"}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    if len(fullname) > 32:
        return jsonify({"error": "Full name must be 32 characters or less"}), 400
    if len(username) > 32:
        return jsonify({"error": "Username must be 32 characters or less"}), 400

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (fullname, username, email, password, role)
            VALUES (%s, %s, %s, %s, 'student')
        """, (fullname, username, email, generate_password_hash(password)))

        cursor.execute("""
            INSERT INTO students (name, email) VALUES (%s, %s)
        """, (fullname, email))

        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"message": "Account created successfully"}), 201

    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "Username or email already exists"}), 409


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"message": "Logged out"})


@app.route("/api/change-password", methods=["POST"])
def change_password():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 403

    data             = request.get_json()
    current_password = data.get("current_password", "")
    new_password     = data.get("new_password", "")

    if not current_password or not new_password:
        return jsonify({"error": "All fields are required"}), 400

    if len(new_password) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400

    if not check_password_hash(user["password"], current_password):
        return jsonify({"error": "Current password is incorrect"}), 401

    if check_password_hash(user["password"], new_password):
        return jsonify({"error": "New password must be different from current password"}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET password = %s WHERE id = %s",
        (generate_password_hash(new_password), user["id"])
    )
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Password updated successfully"})


# ============================================================
# ADMIN API ENDPOINTS
# ============================================================

@app.route("/api/cbc-subjects", methods=["GET"])
def get_cbc_subjects():
    return jsonify(CBC_SUBJECTS)


@app.route("/api/admin/teachers", methods=["GET"])
def get_teachers():
    user = get_current_user()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE role = 'teacher' ORDER BY fullname")
    teachers = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([dict(t) for t in teachers])


@app.route("/api/admin/teachers", methods=["POST"])
def add_teacher():
    user = get_current_user()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data     = request.get_json()
    fullname = data.get("fullname", "").strip()
    username = data.get("username", "").strip()
    email    = data.get("email", "").strip()
    password = data.get("password", "")
    subject  = data.get("subject", "").strip()

    if not fullname or not username or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    # Validate at least one subject selected
    subject_list = [s.strip() for s in subject.split(",") if s.strip()]
    if not subject_list:
        return jsonify({"error": "Please select at least one subject"}), 400
    subject = ",".join(subject_list)  # normalise

    if len(fullname) > 32:
        return jsonify({"error": "Full name must be 32 characters or less"}), 400
    if len(username) > 32:
        return jsonify({"error": "Username must be 32 characters or less"}), 400

    email_regex = r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
    if not re.match(email_regex, email):
        return jsonify({"error": "Please enter a valid email address"}), 400

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (fullname, username, email, password, role, subject)
            VALUES (%s, %s, %s, %s, 'teacher', %s)
        """, (fullname, username, email, generate_password_hash(password), subject))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"message": "Teacher added"}), 201
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "Username or email already exists"}), 409


@app.route("/api/admin/teachers/<int:teacher_id>/subjects", methods=["PATCH"])
def update_teacher_subjects(teacher_id):
    """Update subjects assigned to a teacher — admin only."""
    user = get_current_user()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    subject = data.get("subject", "").strip()

    # Validate at least one subject
    subject_list = [s.strip() for s in subject.split(",") if s.strip()]
    if not subject_list:
        return jsonify({"error": "Please select at least one subject"}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE id = %s AND role = 'teacher'", (teacher_id,))
    if not cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({"error": "Teacher not found"}), 404

    cursor.execute(
        "UPDATE users SET subject = %s WHERE id = %s AND role = 'teacher'",
        (",".join(subject_list), teacher_id)
    )
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"message": "Subjects updated successfully"})


@app.route("/api/admin/teachers/<int:teacher_id>", methods=["DELETE"])
def delete_teacher(teacher_id):
    user = get_current_user()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = %s AND role = 'teacher'", (teacher_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"message": "Teacher deleted"})


@app.route("/api/admin/stats", methods=["GET"])
def admin_stats():
    user = get_current_user()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as c FROM students")
    total_students = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM users WHERE role='teacher'")
    total_teachers = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM grades")
    total_grades = cursor.fetchone()["c"]
    cursor.execute("SELECT grade FROM grades")
    grades = [g["grade"] for g in cursor.fetchall()]
    overall_avg = round(sum(grades) / len(grades), 2) if grades else 0
    cursor.close()
    conn.close()

    return jsonify({
        "total_students":  total_students,
        "total_teachers":  total_teachers,
        "total_grades":    total_grades,
        "overall_average": overall_avg
    })


@app.route("/api/admin/users/<int:user_id>/reset-password", methods=["POST"])
def reset_user_password(user_id):
    admin = get_current_user()
    if not admin or admin["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    target_user = cursor.fetchone()

    if not target_user:
        cursor.close()
        conn.close()
        return jsonify({"error": "User not found"}), 404

    new_password = target_user["username"]
    cursor.execute("UPDATE users SET password = %s WHERE id = %s",
                   (generate_password_hash(new_password), user_id))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({
        "message":      "Password reset successfully",
        "new_password": new_password
    })


@app.route("/api/admin/reset-student-password", methods=["POST"])
def reset_student_password():
    admin = get_current_user()
    if not admin or admin["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data  = request.get_json()
    email = data.get("email", "").strip()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        return jsonify({"error": "User not found"}), 404

    new_password = user["username"]
    cursor.execute("UPDATE users SET password = %s WHERE email = %s",
                   (generate_password_hash(new_password), email))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({
        "message":      "Password reset successfully",
        "new_password": new_password
    })


# ============================================================
# STUDENT & GRADE API ENDPOINTS
# ============================================================

@app.route("/api/students", methods=["GET"])
def get_students():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM students ORDER BY name")
    students = cursor.fetchall()

    # For teachers with multiple subjects, split and filter by any of their subjects
    teacher_subjects = [s.strip() for s in user["subject"].split(",")] if user.get("subject") else []

    result = []
    for s in students:
        if user["role"] == "teacher" and teacher_subjects:
            placeholders = ",".join(["%s"] * len(teacher_subjects))
            cursor.execute(
                f"SELECT * FROM grades WHERE student_id = %s AND subject IN ({placeholders})",
                [s["id"]] + teacher_subjects
            )
        else:
            cursor.execute("SELECT * FROM grades WHERE student_id = %s", (s["id"],))

        grade_list = [dict(g) for g in cursor.fetchall()]
        avg    = round(sum(g["grade"] for g in grade_list) / len(grade_list), 2) if grade_list else None
        status = cbc_status(avg)

        result.append({
            "id": s["id"], "name": s["name"], "email": s["email"],
            "grades": grade_list, "average": avg, "status": status
        })

    cursor.close()
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

    username         = email.split("@")[0]
    default_password = generate_password_hash(username)

    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE email = %s OR username = %s", (email, username))
        existing_user = cursor.fetchone()

        if not existing_user:
            cursor.execute("""
                INSERT INTO users (fullname, username, email, password, role)
                VALUES (%s, %s, %s, %s, 'student')
            """, (name, username, email, default_password))

        cursor.execute("INSERT INTO students (name, email) VALUES (%s, %s)", (name, email))
        conn.commit()

        cursor.execute("SELECT * FROM students WHERE email = %s", (email,))
        student = cursor.fetchone()
        cursor.close()
        conn.close()

        return jsonify({
            "message":    "Student added",
            "student":    dict(student),
            "login_info": {"username": username, "password": username}
        }), 201

    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "Email already exists"}), 409


@app.route("/api/students/<int:student_id>", methods=["DELETE"])
def delete_student(student_id):
    user = get_current_user()
    if not user or user["role"] not in ["admin", "teacher"]:
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM grades WHERE student_id = %s", (student_id,))
    cursor.execute("DELETE FROM students WHERE id = %s", (student_id,))
    conn.commit()
    cursor.close()
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
    comment    = data.get("comment", "").strip() if data.get("comment") else None

    if not student_id or not subject or grade is None:
        return jsonify({"error": "student_id, subject, and grade are required"}), 400

    if comment and len(comment) > 500:
        return jsonify({"error": "Comment must be 500 characters or less"}), 400

    if not (0 <= float(grade) <= float(max_grade)):
        return jsonify({"error": "Grade must be between 0 and max_grade"}), 400

    conn = get_db()
    cursor = conn.cursor()

    # Prevent teachers from adding duplicate subject grade for same student
    if user["role"] == "teacher":
        cursor.execute("""
            SELECT id FROM grades
            WHERE student_id = %s AND subject = %s AND teacher_id = %s
        """, (student_id, subject, user["id"]))
        existing = cursor.fetchone()
        if existing:
            cursor.close()
            conn.close()
            return jsonify({"error": f"You have already added a grade for '{subject}' for this student. Please use the edit option to update it."}), 409

    cursor.execute("""
        INSERT INTO grades (student_id, subject, grade, max_grade, comment, teacher_id)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (student_id, subject, grade, max_grade, comment, user["id"]))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"message": "Grade added"}), 201

@app.route("/api/grades/<int:grade_id>", methods=["DELETE"])
def delete_grade(grade_id):
    user = get_current_user()
    if not user or user["role"] not in ["admin", "teacher"]:
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM grades WHERE id = %s", (grade_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"message": "Grade deleted"})


@app.route("/api/stats", methods=["GET"])
def get_stats():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    cursor = conn.cursor()

    # For teachers, scope stats to their subjects only
    teacher_subjects = []
    if user["role"] == "teacher" and user.get("subject"):
        teacher_subjects = [s.strip() for s in user["subject"].split(",") if s.strip()]

    cursor.execute("SELECT COUNT(*) as c FROM students")
    total_students = cursor.fetchone()["c"]

    if teacher_subjects:
        placeholders = ",".join(["%s"] * len(teacher_subjects))
        cursor.execute(f"SELECT grade FROM grades WHERE subject IN ({placeholders})", teacher_subjects)
    else:
        cursor.execute("SELECT grade FROM grades")
    grades = [g["grade"] for g in cursor.fetchall()]
    overall_avg = round(sum(grades) / len(grades), 2) if grades else 0

    if teacher_subjects:
        placeholders = ",".join(["%s"] * len(teacher_subjects))
        cursor.execute(f"""
            SELECT COUNT(*) as c FROM (
                SELECT student_id, AVG(grade) as avg FROM grades
                WHERE subject IN ({placeholders})
                GROUP BY student_id HAVING AVG(grade) >= 50
            ) sub
        """, teacher_subjects)
    else:
        cursor.execute("""
            SELECT COUNT(*) as c FROM (
                SELECT student_id, AVG(grade) as avg FROM grades
                GROUP BY student_id HAVING AVG(grade) >= 50
            ) sub
        """)
    meeting = cursor.fetchone()["c"]
    cursor.close()
    conn.close()

    return jsonify({
        "total_students":    total_students,
        "overall_average":   overall_avg,
        "meeting_students":  meeting,
        "below_students":    total_students - meeting
    })


@app.route("/api/my-grades", methods=["GET"])
def my_grades():
    user = get_current_user()
    if not user or user["role"] != "student":
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM students WHERE email = %s", (user["email"],))
    student = cursor.fetchone()

    if not student:
        cursor.close()
        conn.close()
        return jsonify({"grades": [], "average": None, "status": "No Grades"})

    cursor.execute("SELECT * FROM grades WHERE student_id = %s", (student["id"],))
    grade_list = [dict(g) for g in cursor.fetchall()]
    avg    = round(sum(g["grade"] for g in grade_list) / len(grade_list), 2) if grade_list else None
    status = cbc_status(avg)

    cursor.close()
    conn.close()
    return jsonify({
        "student": dict(student),
        "grades":  grade_list,
        "average": avg,
        "status":  status
    })


# ============================================================
# EDIT GRADE
# ============================================================

@app.route("/api/grades/<int:grade_id>", methods=["PUT"])
def edit_grade(grade_id):
    """Edit an existing grade — teachers and admin only."""
    user = get_current_user()
    if not user or user["role"] not in ["admin", "teacher"]:
        return jsonify({"error": "Unauthorized"}), 403

    data      = request.get_json()
    grade     = data.get("grade")
    max_grade = data.get("max_grade")
    subject   = data.get("subject", "").strip()
    comment   = data.get("comment")  # None means "don't change", "" means "clear it"

    if grade is None:
        return jsonify({"error": "Grade is required"}), 400

    conn = get_db()
    cursor = conn.cursor()

    # Verify grade exists
    cursor.execute("SELECT * FROM grades WHERE id = %s", (grade_id,))
    existing = cursor.fetchone()
    if not existing:
        cursor.close()
        conn.close()
        return jsonify({"error": "Grade not found"}), 404

    # Build update query dynamically
    updates = ["grade = %s"]
    values  = [grade]
    if max_grade is not None:
        updates.append("max_grade = %s")
        values.append(max_grade)
    if subject:
        updates.append("subject = %s")
        values.append(subject)
    if comment is not None:
        updates.append("comment = %s")
        stripped = comment.strip() if comment else None
        if stripped and len(stripped) > 500:
            cursor.close()
            conn.close()
            return jsonify({"error": "Comment must be 500 characters or less"}), 400
        values.append(stripped)

    values.append(grade_id)
    cursor.execute(f"UPDATE grades SET {', '.join(updates)} WHERE id = %s", values)
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"message": "Grade updated successfully"})


# ============================================================
# SEARCH ENDPOINTS
# ============================================================

@app.route("/api/students/search", methods=["GET"])
def search_students():
    """Search students by name or email."""
    user = get_current_user()
    if not user or user["role"] not in ["admin", "teacher"]:
        return jsonify({"error": "Unauthorized"}), 403

    query = request.args.get("q", "").strip()
    if not query:
        return jsonify([])

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM students
        WHERE LOWER(name) LIKE %s OR LOWER(email) LIKE %s
        ORDER BY name
    """, (f"%{query.lower()}%", f"%{query.lower()}%"))
    students = cursor.fetchall()

    result = []
    for s in students:
        cursor.execute("SELECT * FROM grades WHERE student_id = %s", (s["id"],))
        grade_list = [dict(g) for g in cursor.fetchall()]
        avg    = round(sum(g["grade"] for g in grade_list) / len(grade_list), 2) if grade_list else None
        status = cbc_status(avg)
        result.append({
            "id": s["id"], "name": s["name"], "email": s["email"],
            "grades": grade_list, "average": avg, "status": status
        })

    cursor.close()
    conn.close()
    return jsonify(result)


@app.route("/api/teachers/search", methods=["GET"])
def search_teachers():
    """Search teachers by name, username or subject — admin only."""
    user = get_current_user()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    query = request.args.get("q", "").strip()
    if not query:
        return jsonify([])

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM users
        WHERE role = 'teacher' AND (
            LOWER(fullname) LIKE %s OR
            LOWER(username) LIKE %s OR
            LOWER(subject)  LIKE %s
        )
        ORDER BY fullname
    """, (f"%{query.lower()}%", f"%{query.lower()}%", f"%{query.lower()}%"))
    teachers = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([dict(t) for t in teachers])


# ============================================================
# REPORT ENDPOINTS
# ============================================================

@app.route("/api/my-report", methods=["GET"])
def my_report():
    """Return full report data for the logged in student."""
    user = get_current_user()
    if not user or user["role"] != "student":
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM students WHERE email = %s", (user["email"],))
    student = cursor.fetchone()

    if not student:
        cursor.close()
        conn.close()
        return jsonify({"error": "Student record not found"}), 404

    cursor.execute("""
        SELECT g.*, u.fullname as teacher_name
        FROM grades g
        LEFT JOIN users u ON g.teacher_id = u.id
        WHERE g.student_id = %s
        ORDER BY g.created_at DESC
    """, (student["id"],))
    grade_list = [dict(g) for g in cursor.fetchall()]

    # Fix 2: Format dates as DD/MM/YYYY (Kenyan format)
    for g in grade_list:
        if g.get("created_at"):
            g["date_added"] = g["created_at"].strftime("%d/%m/%Y")
        else:
            g["date_added"] = "—"

    avg    = round(sum(g["grade"] for g in grade_list) / len(grade_list), 2) if grade_list else None
    status = cbc_status(avg)

    # Fix 4: Sort by official KNEC/MoE CBC subject order
    KNEC_ORDER = [
        "English", "Kiswahili", "Mathematics", "Integrated Science",
        "Social Studies", "Religious Education (CRE)", "Religious Education (IRE)",
        "Religious Education (HRE)", "Pre-Technical Studies", "Business Studies",
        "Agriculture", "Nutrition & Home Science", "Computer Studies",
        "Creative Arts & Sports",
    ]
    grade_list.sort(key=lambda g: KNEC_ORDER.index(g["subject"]) if g["subject"] in KNEC_ORDER else len(KNEC_ORDER))

    # Subject breakdown
    subjects = {}
    for g in grade_list:
        subj = g["subject"]
        if subj not in subjects:
            subjects[subj] = []
        subjects[subj].append(g["grade"])
    subject_avgs = {s: round(sum(v)/len(v), 2) for s, v in subjects.items()}

    cursor.close()
    conn.close()
    return jsonify({
        "student":      dict(student),
        "fullname":     user["fullname"],
        "email":        user["email"],
        "grades":       grade_list,
        "average":      avg,
        "status":       status,
        "subject_avgs": subject_avgs,
        "total_grades": len(grade_list)
    })


@app.route("/api/admin/school-report", methods=["GET"])
def school_report():
    """Return full school report — admin only."""
    user = get_current_user()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    cursor = conn.cursor()

    # All students with their averages
    cursor.execute("SELECT * FROM students ORDER BY name")
    students = cursor.fetchall()

    student_data = []
    for s in students:
        cursor.execute("SELECT grade FROM grades WHERE student_id = %s", (s["id"],))
        grades = [g["grade"] for g in cursor.fetchall()]
        avg    = round(sum(grades) / len(grades), 2) if grades else None
        status = cbc_status(avg)
        student_data.append({
            "name": s["name"], "email": s["email"],
            "average": avg, "status": status,
            "total_grades": len(grades)
        })

    # Teacher count
    cursor.execute("SELECT COUNT(*) as c FROM users WHERE role='teacher'")
    total_teachers = cursor.fetchone()["c"]

    # Overall stats
    cursor.execute("SELECT grade FROM grades")
    all_grades = [g["grade"] for g in cursor.fetchall()]
    overall_avg = round(sum(all_grades) / len(all_grades), 2) if all_grades else 0
    passing = sum(1 for s in student_data if s["status"] in ["EE", "ME"])
    failing = sum(1 for s in student_data if s["status"] in ["AE", "BE"])

    cursor.close()
    conn.close()
    return jsonify({
        "students":        student_data,
        "total_students":  len(student_data),
        "total_teachers":  total_teachers,
        "total_grades":    len(all_grades),
        "overall_average": overall_avg,
        "passing":         passing,
        "failing":         failing
    })


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
