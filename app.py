# ============================================================
# app.py — GradeVault Backend (PostgreSQL version)
# ============================================================

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import psycopg2.extras
import re
import os

app = Flask(__name__)
app.secret_key = "gradevault_secret_key_2024"

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
# PAGE ROUTES
# ============================================================

@app.route("/")
def home():
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

    if not fullname or not username or not email or not password or not subject:
        return jsonify({"error": "All fields are required"}), 400

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

    result = []
    for s in students:
        if user["role"] == "teacher":
            cursor.execute(
                "SELECT * FROM grades WHERE student_id = %s AND subject = %s",
                (s["id"], user["subject"])
            )
        else:
            cursor.execute("SELECT * FROM grades WHERE student_id = %s", (s["id"],))

        grade_list = [dict(g) for g in cursor.fetchall()]
        avg    = round(sum(g["grade"] for g in grade_list) / len(grade_list), 2) if grade_list else None
        status = "Pass" if avg and avg >= 50 else ("Fail" if avg is not None else "No Grades")

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
    cursor.execute("SELECT COUNT(*) as c FROM students")
    total_students = cursor.fetchone()["c"]
    cursor.execute("SELECT grade FROM grades")
    grades = [g["grade"] for g in cursor.fetchall()]
    overall_avg = round(sum(grades) / len(grades), 2) if grades else 0
    cursor.execute("""
        SELECT COUNT(*) as c FROM (
            SELECT student_id, AVG(grade) as avg FROM grades
            GROUP BY student_id HAVING AVG(grade) >= 50
        ) sub
    """)
    passing = cursor.fetchone()["c"]
    cursor.close()
    conn.close()

    return jsonify({
        "total_students":   total_students,
        "overall_average":  overall_avg,
        "passing_students": passing,
        "failing_students": total_students - passing
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
    status = "Pass" if avg and avg >= 50 else ("Fail" if avg is not None else "No Grades")

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
        status = "Pass" if avg and avg >= 50 else ("Fail" if avg is not None else "No Grades")
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
    avg    = round(sum(g["grade"] for g in grade_list) / len(grade_list), 2) if grade_list else None
    status = "Pass" if avg and avg >= 50 else ("Fail" if avg is not None else "No Grades")

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
        status = "Pass" if avg and avg >= 50 else ("Fail" if avg is not None else "No Grades")
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
    passing = sum(1 for s in student_data if s["status"] == "Pass")
    failing = sum(1 for s in student_data if s["status"] == "Fail")

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
