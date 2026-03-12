# ============================================================
# app.py  —  GradeVault (Flask + PostgreSQL + WebAuthn)
# ============================================================
import sys, logging
logging.basicConfig(level=logging.INFO, stream=sys.stderr, force=True)

# Load .env file for local development (ignored on Render)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2, psycopg2.extras, re, os, secrets, requests
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "gradevault_secret_key_2024"
app.config["SESSION_PERMANENT"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

# ── Email ────────────────────────────────────────────────────
BREVO_API_KEY  = os.environ.get("BREVO_API_KEY")
MAIL_FROM      = os.environ.get("MAIL_FROM", "fidelclinton4@gmail.com")
MAIL_FROM_NAME = os.environ.get("MAIL_FROM_NAME", "GradeVault")
APP_BASE_URL   = os.environ.get("APP_BASE_URL", "https://grade-tracker-pq0y.onrender.com")


def send_reset_email(to_email, token):
    link = f"{APP_BASE_URL}/reset-password?token={token}"
    html = f"""<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;background:#0f1117;color:#f0f0f0;border-radius:12px;padding:2rem">
      <h2 style="color:#f5c518">Password Reset</h2>
      <p style="color:#aaa">You requested a password reset for your GradeVault account.</p>
      <a href="{link}" style="display:inline-block;background:#f5c518;color:#0f1117;font-weight:700;padding:12px 28px;border-radius:8px;text-decoration:none">Reset My Password</a>
      <p style="color:#888;font-size:0.8rem;margin-top:1.5rem">Expires in 30 minutes. If you didn't request this, ignore this email.</p>
    </div>"""
    r = requests.post("https://api.brevo.com/v3/smtp/email",
        headers={"accept":"application/json","api-key":BREVO_API_KEY,"content-type":"application/json"},
        json={"sender":{"name":MAIL_FROM_NAME,"email":MAIL_FROM},"to":[{"email":to_email}],
              "subject":"GradeVault — Password Reset","htmlContent":html,
              "textContent":f"Reset your password: {link}\nExpires in 30 minutes."},
        timeout=20)
    if r.status_code not in (200, 201):
        raise Exception(f"Brevo {r.status_code}: {r.text}")


@app.route("/test-email")
def test_email():
    try: send_reset_email("fidelclinton4@gmail.com","testtoken123"); return "EMAIL SENT OK"
    except Exception as e: return f"EMAIL FAILED: {e}"


# ── DB ───────────────────────────────────────────────────────
def get_db():
    return psycopg2.connect(os.environ["DATABASE_URL"],
                            cursor_factory=psycopg2.extras.RealDictCursor)


def init_db():
    conn = get_db(); cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY, fullname TEXT NOT NULL, username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'student', subject TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS students (
        id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id),
        name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS grades (
        id SERIAL PRIMARY KEY, student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
        subject TEXT NOT NULL, grade REAL NOT NULL, max_grade REAL DEFAULT 100,
        comment TEXT, teacher_id INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    cur.execute("ALTER TABLE grades ADD COLUMN IF NOT EXISTS comment TEXT")
    cur.execute("""CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        token TEXT UNIQUE NOT NULL, expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    conn.commit()
    cur.execute("SELECT id FROM users WHERE role='admin'")
    if not cur.fetchone():
        cur.execute("INSERT INTO users (fullname,username,email,password,role) VALUES (%s,%s,%s,%s,'admin')",
            ("Administrator","admin","admin@gradevault.com",generate_password_hash("admin123")))
        conn.commit()
        print("Default admin → username: admin | password: admin123")
    cur.close(); conn.close()


def get_current_user():
    uid = session.get("user_id")
    if not uid: return None
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=%s", (uid,))
    u = cur.fetchone(); cur.close(); conn.close()
    return u


# ── CBC ──────────────────────────────────────────────────────
CBC_SUBJECTS = [
    "English","Kiswahili","Mathematics","Integrated Science","Social Studies",
    "Religious Education (CRE)","Religious Education (IRE)","Religious Education (HRE)",
    "Pre-Technical Studies","Business Studies","Computer Studies","Agriculture",
    "Nutrition & Home Science","Creative Arts & Sports",
]

def cbc_status(avg):
    if avg is None: return "No Grades"
    if avg >= 75: return "EE"
    if avg >= 50: return "ME"
    if avg >= 25: return "AE"
    return "BE"


# ── Page routes ──────────────────────────────────────────────
@app.route("/")
def home():
    u = get_current_user()
    return redirect(url_for(u["role"]+"_dashboard")) if u else redirect(url_for("login_page"))

@app.route("/login")
def login_page(): return render_template("login.html")

@app.route("/register")
def register_page(): return render_template("register.html")

@app.route("/forgot-password")
def forgot_password_page(): return render_template("forgot_password.html")

@app.route("/reset-password")
def reset_password_page():
    return render_template("reset_password.html", token=request.args.get("token",""))

@app.route("/dashboard/admin")
def admin_dashboard():
    u = get_current_user()
    if not u or u["role"] != "admin": return redirect(url_for("login_page"))
    return render_template("dashboard_admin.html", user=dict(u))

@app.route("/dashboard/teacher")
def teacher_dashboard():
    u = get_current_user()
    if not u or u["role"] != "teacher": return redirect(url_for("login_page"))
    return render_template("dashboard_teacher.html", user=dict(u))

@app.route("/dashboard/student")
def student_dashboard():
    u = get_current_user()
    if not u or u["role"] != "student": return redirect(url_for("login_page"))
    return render_template("dashboard_student.html", user=dict(u))


# ── Auth API ─────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def api_login():
    d = request.get_json()
    username, password = d.get("username","").strip(), d.get("password","")
    if not username or not password:
        return jsonify({"error":"Please enter both username and password"}), 400
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=%s", (username,))
    u = cur.fetchone(); cur.close(); conn.close()
    if not u or not check_password_hash(u["password"], password):
        return jsonify({"error":"Invalid username or password"}), 401
    session["user_id"] = u["id"]; session["role"] = u["role"]
    rd = {"admin":"/dashboard/admin","teacher":"/dashboard/teacher","student":"/dashboard/student"}
    return jsonify({"message":"Login successful","role":u["role"],"fullname":u["fullname"],"redirect":rd[u["role"]]})


@app.route("/api/register", methods=["POST"])
def api_register():
    d = request.get_json()
    fn,un,em,pw = d.get("fullname","").strip(),d.get("username","").strip(),d.get("email","").strip(),d.get("password","")
    if not all([fn,un,em,pw]): return jsonify({"error":"All fields are required"}), 400
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$",em): return jsonify({"error":"Invalid email address"}), 400
    if len(pw)<6: return jsonify({"error":"Password must be at least 6 characters"}), 400
    if len(fn)>32: return jsonify({"error":"Full name must be 32 characters or less"}), 400
    if len(un)>32: return jsonify({"error":"Username must be 32 characters or less"}), 400
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("INSERT INTO users (fullname,username,email,password,role) VALUES (%s,%s,%s,%s,'student')",
            (fn,un,em,generate_password_hash(pw)))
        cur.execute("INSERT INTO students (name,email) VALUES (%s,%s)", (fn,em))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"message":"Account created successfully"}), 201
    except psycopg2.errors.UniqueViolation:
        conn.rollback(); return jsonify({"error":"Username or email already exists"}), 409


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear(); return jsonify({"message":"Logged out"})


@app.route("/api/change-password", methods=["POST"])
def change_password():
    u = get_current_user()
    if not u: return jsonify({"error":"Unauthorized"}), 403
    d = request.get_json(); cur_pw,new_pw = d.get("current_password",""),d.get("new_password","")
    if not cur_pw or not new_pw: return jsonify({"error":"All fields are required"}), 400
    if len(new_pw)<6: return jsonify({"error":"Password must be at least 6 characters"}), 400
    if not check_password_hash(u["password"],cur_pw): return jsonify({"error":"Current password is incorrect"}), 401
    if check_password_hash(u["password"],new_pw): return jsonify({"error":"New password must be different"}), 400
    conn = get_db(); cur = conn.cursor()
    cur.execute("UPDATE users SET password=%s WHERE id=%s", (generate_password_hash(new_pw),u["id"]))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"message":"Password updated successfully"})


# ── Password reset ────────────────────────────────────────────
@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    d = request.get_json(); email = d.get("email","").strip().lower()
    if not email: return jsonify({"error":"Email is required"}), 400
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT id,email FROM users WHERE LOWER(email)=%s", (email,))
    u = cur.fetchone()
    if not u:
        cur.close(); conn.close()
        return jsonify({"message":"If that email exists, a reset link has been sent."})
    token = secrets.token_urlsafe(48)
    expires = datetime.utcnow() + timedelta(minutes=30)
    cur.execute("UPDATE password_reset_tokens SET used=TRUE WHERE user_id=%s AND used=FALSE", (u["id"],))
    cur.execute("INSERT INTO password_reset_tokens (user_id,token,expires_at) VALUES (%s,%s,%s)", (u["id"],token,expires))
    conn.commit(); cur.close(); conn.close()
    try: send_reset_email(u["email"], token)
    except Exception as e: return jsonify({"error":f"Email failed: {e}"}), 500
    return jsonify({"message":"If that email exists, a reset link has been sent."})


@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    d = request.get_json(); token,pw = d.get("token","").strip(),d.get("password","")
    if not token or not pw: return jsonify({"error":"Token and password are required"}), 400
    if len(pw)<6: return jsonify({"error":"Password must be at least 6 characters"}), 400
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT id,user_id,expires_at,used FROM password_reset_tokens WHERE token=%s",(token,))
    rec = cur.fetchone()
    if not rec: cur.close(); conn.close(); return jsonify({"error":"Invalid or expired reset link."}), 400
    if rec["used"]: cur.close(); conn.close(); return jsonify({"error":"This link has already been used."}), 400
    if datetime.utcnow() > rec["expires_at"]: cur.close(); conn.close(); return jsonify({"error":"This link has expired. Please request a new one."}), 400
    cur.execute("UPDATE users SET password=%s WHERE id=%s",(generate_password_hash(pw),rec["user_id"]))
    cur.execute("UPDATE password_reset_tokens SET used=TRUE WHERE id=%s",(rec["id"],))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"message":"Password reset successfully! You can now log in."})


# ── Admin API ─────────────────────────────────────────────────
@app.route("/api/cbc-subjects")
def get_cbc_subjects(): return jsonify(CBC_SUBJECTS)


@app.route("/api/admin/stats")
def admin_stats():
    u = get_current_user()
    if not u or u["role"]!="admin": return jsonify({"error":"Unauthorized"}), 403
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as c FROM students"); ts = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM users WHERE role='teacher'"); tt = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM grades"); tg = cur.fetchone()["c"]
    cur.execute("SELECT grade FROM grades"); gs = [g["grade"] for g in cur.fetchall()]
    cur.close(); conn.close()
    return jsonify({"total_students":ts,"total_teachers":tt,"total_grades":tg,
                    "overall_average":round(sum(gs)/len(gs),2) if gs else 0})


@app.route("/api/admin/teachers", methods=["GET"])
def get_teachers():
    u = get_current_user()
    if not u or u["role"]!="admin": return jsonify({"error":"Unauthorized"}), 403
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE role='teacher' ORDER BY fullname")
    rows = cur.fetchall(); cur.close(); conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin/teachers", methods=["POST"])
def add_teacher():
    u = get_current_user()
    if not u or u["role"]!="admin": return jsonify({"error":"Unauthorized"}), 403
    d = request.get_json()
    fn,un,em,pw,sub = (d.get("fullname","").strip(),d.get("username","").strip(),
        d.get("email","").strip(),d.get("password",""),d.get("subject","").strip())
    if not all([fn,un,em,pw]): return jsonify({"error":"All fields are required"}), 400
    sl = [s.strip() for s in sub.split(",") if s.strip()]
    if not sl: return jsonify({"error":"Please select at least one subject"}), 400
    if len(fn)>32: return jsonify({"error":"Full name must be 32 characters or less"}), 400
    if len(un)>32: return jsonify({"error":"Username must be 32 characters or less"}), 400
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$",em): return jsonify({"error":"Invalid email address"}), 400
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("INSERT INTO users (fullname,username,email,password,role,subject) VALUES (%s,%s,%s,%s,'teacher',%s)",
            (fn,un,em,generate_password_hash(pw),",".join(sl)))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"message":"Teacher added"}), 201
    except psycopg2.errors.UniqueViolation:
        conn.rollback(); return jsonify({"error":"Username or email already exists"}), 409


@app.route("/api/admin/teachers/<int:tid>/subjects", methods=["PATCH"])
def update_teacher_subjects(tid):
    u = get_current_user()
    if not u or u["role"]!="admin": return jsonify({"error":"Unauthorized"}), 403
    sl = [s.strip() for s in request.get_json().get("subject","").split(",") if s.strip()]
    if not sl: return jsonify({"error":"Please select at least one subject"}), 400
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE id=%s AND role='teacher'",(tid,))
    if not cur.fetchone(): cur.close(); conn.close(); return jsonify({"error":"Teacher not found"}), 404
    cur.execute("UPDATE users SET subject=%s WHERE id=%s AND role='teacher'",(",".join(sl),tid))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"message":"Subjects updated successfully"})


@app.route("/api/admin/teachers/<int:tid>", methods=["DELETE"])
def delete_teacher(tid):
    u = get_current_user()
    if not u or u["role"]!="admin": return jsonify({"error":"Unauthorized"}), 403
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id=%s AND role='teacher'",(tid,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"message":"Teacher deleted"})


@app.route("/api/admin/users/<int:uid>/reset-password", methods=["POST"])
def reset_user_password(uid):
    a = get_current_user()
    if not a or a["role"]!="admin": return jsonify({"error":"Unauthorized"}), 403
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=%s",(uid,))
    tu = cur.fetchone()
    if not tu: cur.close(); conn.close(); return jsonify({"error":"User not found"}), 404
    cur.execute("UPDATE users SET password=%s WHERE id=%s",(generate_password_hash(tu["username"]),uid))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"message":"Password reset","new_password":tu["username"]})


@app.route("/api/admin/reset-student-password", methods=["POST"])
def reset_student_password():
    a = get_current_user()
    if not a or a["role"]!="admin": return jsonify({"error":"Unauthorized"}), 403
    email = request.get_json().get("email","").strip()
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email=%s",(email,))
    tu = cur.fetchone()
    if not tu: cur.close(); conn.close(); return jsonify({"error":"User not found"}), 404
    cur.execute("UPDATE users SET password=%s WHERE email=%s",(generate_password_hash(tu["username"]),email))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"message":"Password reset","new_password":tu["username"]})


@app.route("/api/admin/school-report")
def school_report():
    u = get_current_user()
    if not u or u["role"]!="admin": return jsonify({"error":"Unauthorized"}), 403
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM students ORDER BY name"); students = cur.fetchall()
    data = []
    for s in students:
        cur.execute("SELECT grade FROM grades WHERE student_id=%s",(s["id"],))
        gs = [g["grade"] for g in cur.fetchall()]
        avg = round(sum(gs)/len(gs),2) if gs else None
        data.append({"name":s["name"],"email":s["email"],"average":avg,"status":cbc_status(avg),"total_grades":len(gs)})
    cur.execute("SELECT COUNT(*) as c FROM users WHERE role='teacher'"); tt = cur.fetchone()["c"]
    cur.execute("SELECT grade FROM grades"); all_gs = [g["grade"] for g in cur.fetchall()]
    cur.close(); conn.close()
    return jsonify({"students":data,"total_students":len(data),"total_teachers":tt,"total_grades":len(all_gs),
                    "overall_average":round(sum(all_gs)/len(all_gs),2) if all_gs else 0,
                    "passing":sum(1 for s in data if s["status"] in ["EE","ME"]),
                    "failing":sum(1 for s in data if s["status"] in ["AE","BE"])})


# ── Students & Grades ─────────────────────────────────────────
@app.route("/api/students", methods=["GET"])
def get_students():
    u = get_current_user()
    if not u: return jsonify({"error":"Unauthorized"}), 403
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM students ORDER BY name"); students = cur.fetchall()
    tsubs = [s.strip() for s in u["subject"].split(",")] if u.get("subject") else []
    result = []
    for s in students:
        if u["role"]=="teacher" and tsubs:
            ph = ",".join(["%s"]*len(tsubs))
            cur.execute(f"SELECT * FROM grades WHERE student_id=%s AND subject IN ({ph})",[s["id"]]+tsubs)
        else:
            cur.execute("SELECT * FROM grades WHERE student_id=%s",(s["id"],))
        gl = [dict(g) for g in cur.fetchall()]
        avg = round(sum(g["grade"] for g in gl)/len(gl),2) if gl else None
        result.append({"id":s["id"],"name":s["name"],"email":s["email"],"grades":gl,"average":avg,"status":cbc_status(avg)})
    cur.close(); conn.close()
    return jsonify(result)


@app.route("/api/students", methods=["POST"])
def add_student():
    u = get_current_user()
    if not u or u["role"] not in ["admin","teacher"]: return jsonify({"error":"Unauthorized"}), 403
    d = request.get_json(); name,email = d.get("name","").strip(),d.get("email","").strip()
    if not name or not email: return jsonify({"error":"Name and email are required"}), 400
    un = email.split("@")[0]
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email=%s OR username=%s",(email,un))
        if not cur.fetchone():
            cur.execute("INSERT INTO users (fullname,username,email,password,role) VALUES (%s,%s,%s,%s,'student')",
                (name,un,email,generate_password_hash(un)))
        cur.execute("INSERT INTO students (name,email) VALUES (%s,%s)",(name,email))
        conn.commit()
        cur.execute("SELECT * FROM students WHERE email=%s",(email,))
        st = cur.fetchone(); cur.close(); conn.close()
        return jsonify({"message":"Student added","student":dict(st),"login_info":{"username":un,"password":un}}), 201
    except psycopg2.errors.UniqueViolation:
        conn.rollback(); return jsonify({"error":"Email already exists"}), 409


@app.route("/api/students/<int:sid>", methods=["DELETE"])
def delete_student(sid):
    u = get_current_user()
    if not u or u["role"] not in ["admin","teacher"]: return jsonify({"error":"Unauthorized"}), 403
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM grades WHERE student_id=%s",(sid,))
    cur.execute("DELETE FROM students WHERE id=%s",(sid,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"message":"Student deleted"})


@app.route("/api/grades", methods=["POST"])
def add_grade():
    u = get_current_user()
    if not u or u["role"] not in ["admin","teacher"]: return jsonify({"error":"Unauthorized"}), 403
    d = request.get_json()
    sid,subj,grade,mg = d.get("student_id"),d.get("subject","").strip(),d.get("grade"),d.get("max_grade",100)
    comment = d.get("comment","").strip() or None
    if not sid or not subj or grade is None: return jsonify({"error":"student_id, subject, and grade are required"}), 400
    if comment and len(comment)>500: return jsonify({"error":"Comment must be 500 characters or less"}), 400
    if not (0 <= float(grade) <= float(mg)): return jsonify({"error":"Grade must be between 0 and max_grade"}), 400
    conn = get_db(); cur = conn.cursor()
    if u["role"]=="teacher":
        cur.execute("SELECT id FROM grades WHERE student_id=%s AND subject=%s AND teacher_id=%s",(sid,subj,u["id"]))
        if cur.fetchone():
            cur.close(); conn.close()
            return jsonify({"error":f"You already added a '{subj}' grade for this student. Use edit to update it."}), 409
    cur.execute("INSERT INTO grades (student_id,subject,grade,max_grade,comment,teacher_id) VALUES (%s,%s,%s,%s,%s,%s)",
        (sid,subj,grade,mg,comment,u["id"]))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"message":"Grade added"}), 201


@app.route("/api/grades/<int:gid>", methods=["PUT"])
def edit_grade(gid):
    u = get_current_user()
    if not u or u["role"] not in ["admin","teacher"]: return jsonify({"error":"Unauthorized"}), 403
    d = request.get_json(); grade = d.get("grade")
    if grade is None: return jsonify({"error":"Grade is required"}), 400
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT id FROM grades WHERE id=%s",(gid,))
    if not cur.fetchone(): cur.close(); conn.close(); return jsonify({"error":"Grade not found"}), 404
    updates,values = ["grade=%s"],[grade]
    if d.get("max_grade") is not None: updates.append("max_grade=%s"); values.append(d["max_grade"])
    if d.get("subject","").strip(): updates.append("subject=%s"); values.append(d["subject"].strip())
    if "comment" in d:
        c = d["comment"].strip() if d["comment"] else None
        if c and len(c)>500: cur.close(); conn.close(); return jsonify({"error":"Comment must be 500 characters or less"}), 400
        updates.append("comment=%s"); values.append(c)
    values.append(gid)
    cur.execute(f"UPDATE grades SET {', '.join(updates)} WHERE id=%s",values)
    conn.commit(); cur.close(); conn.close()
    return jsonify({"message":"Grade updated successfully"})


@app.route("/api/grades/<int:gid>", methods=["DELETE"])
def delete_grade(gid):
    u = get_current_user()
    if not u or u["role"] not in ["admin","teacher"]: return jsonify({"error":"Unauthorized"}), 403
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM grades WHERE id=%s",(gid,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"message":"Grade deleted"})


@app.route("/api/stats")
def get_stats():
    u = get_current_user()
    if not u: return jsonify({"error":"Unauthorized"}), 403
    conn = get_db(); cur = conn.cursor()
    tsubs = [s.strip() for s in u["subject"].split(",")] if u["role"]=="teacher" and u.get("subject") else []
    cur.execute("SELECT COUNT(*) as c FROM students"); ts = cur.fetchone()["c"]
    if tsubs:
        ph = ",".join(["%s"]*len(tsubs))
        cur.execute(f"SELECT grade FROM grades WHERE subject IN ({ph})",tsubs)
    else:
        cur.execute("SELECT grade FROM grades")
    gs = [g["grade"] for g in cur.fetchall()]
    avg = round(sum(gs)/len(gs),2) if gs else 0
    if tsubs:
        ph = ",".join(["%s"]*len(tsubs))
        cur.execute(f"SELECT COUNT(*) as c FROM (SELECT student_id FROM grades WHERE subject IN ({ph}) GROUP BY student_id HAVING AVG(grade)>=50) s",tsubs)
    else:
        cur.execute("SELECT COUNT(*) as c FROM (SELECT student_id FROM grades GROUP BY student_id HAVING AVG(grade)>=50) s")
    meeting = cur.fetchone()["c"]; cur.close(); conn.close()
    return jsonify({"total_students":ts,"overall_average":avg,"meeting_students":meeting,"below_students":ts-meeting})


@app.route("/api/my-grades")
def my_grades():
    u = get_current_user()
    if not u or u["role"]!="student": return jsonify({"error":"Unauthorized"}), 403
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM students WHERE email=%s",(u["email"],))
    st = cur.fetchone()
    if not st: cur.close(); conn.close(); return jsonify({"grades":[],"average":None,"status":"No Grades"})
    cur.execute("SELECT * FROM grades WHERE student_id=%s",(st["id"],))
    gl = [dict(g) for g in cur.fetchall()]
    avg = round(sum(g["grade"] for g in gl)/len(gl),2) if gl else None
    cur.close(); conn.close()
    return jsonify({"student":dict(st),"grades":gl,"average":avg,"status":cbc_status(avg)})


@app.route("/api/my-report")
def my_report():
    u = get_current_user()
    if not u or u["role"]!="student": return jsonify({"error":"Unauthorized"}), 403
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM students WHERE email=%s",(u["email"],))
    st = cur.fetchone()
    if not st: cur.close(); conn.close(); return jsonify({"error":"Student record not found"}), 404
    cur.execute("""SELECT g.*, u2.fullname as teacher_name FROM grades g
                   LEFT JOIN users u2 ON g.teacher_id=u2.id
                   WHERE g.student_id=%s ORDER BY g.created_at DESC""",(st["id"],))
    gl = [dict(g) for g in cur.fetchall()]
    for g in gl:
        g["date_added"] = g["created_at"].strftime("%d/%m/%Y") if g.get("created_at") else "—"
    avg = round(sum(g["grade"] for g in gl)/len(gl),2) if gl else None
    KNEC = ["English","Kiswahili","Mathematics","Integrated Science","Social Studies",
            "Religious Education (CRE)","Religious Education (IRE)","Religious Education (HRE)",
            "Pre-Technical Studies","Business Studies","Agriculture","Nutrition & Home Science",
            "Computer Studies","Creative Arts & Sports"]
    gl.sort(key=lambda g: KNEC.index(g["subject"]) if g["subject"] in KNEC else len(KNEC))
    subs = {}
    for g in gl: subs.setdefault(g["subject"],[]).append(g["grade"])
    cur.close(); conn.close()
    return jsonify({"student":dict(st),"fullname":u["fullname"],"email":u["email"],"grades":gl,
                    "average":avg,"status":cbc_status(avg),"total_grades":len(gl),
                    "subject_avgs":{s:round(sum(v)/len(v),2) for s,v in subs.items()}})


@app.route("/api/students/search")
def search_students():
    u = get_current_user()
    if not u or u["role"] not in ["admin","teacher"]: return jsonify({"error":"Unauthorized"}), 403
    q = request.args.get("q","").strip()
    if not q: return jsonify([])
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM students WHERE LOWER(name) LIKE %s OR LOWER(email) LIKE %s ORDER BY name",
                (f"%{q.lower()}%",f"%{q.lower()}%"))
    students = cur.fetchall(); result = []
    for s in students:
        cur.execute("SELECT * FROM grades WHERE student_id=%s",(s["id"],))
        gl = [dict(g) for g in cur.fetchall()]
        avg = round(sum(g["grade"] for g in gl)/len(gl),2) if gl else None
        result.append({"id":s["id"],"name":s["name"],"email":s["email"],"grades":gl,"average":avg,"status":cbc_status(avg)})
    cur.close(); conn.close(); return jsonify(result)


@app.route("/api/teachers/search")
def search_teachers():
    u = get_current_user()
    if not u or u["role"]!="admin": return jsonify({"error":"Unauthorized"}), 403
    q = request.args.get("q","").strip()
    if not q: return jsonify([])
    conn = get_db(); cur = conn.cursor()
    cur.execute("""SELECT * FROM users WHERE role='teacher' AND
                   (LOWER(fullname) LIKE %s OR LOWER(username) LIKE %s OR LOWER(subject) LIKE %s) ORDER BY fullname""",
                (f"%{q.lower()}%",f"%{q.lower()}%",f"%{q.lower()}%"))
    rows = cur.fetchall(); cur.close(); conn.close()
    return jsonify([dict(r) for r in rows])


# ── Start ─────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT",5000)))
