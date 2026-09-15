from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, jsonify
from datetime import datetime
import config
from models import init_db, get_db, log_audit_event
from crypto_utils import encrypt_question_paper, decrypt_question_paper
from watermark_utils import generate_watermarked_pdf
from auth import login_required, verify_totp

app = Flask(__name__)
app.config.from_object(config)

# Initialize Database
init_db()

@app.route("/")
def dashboard():
    if "user" in session:
        role = session.get("role")
        if role in ["FACULTY", "REVIEWER"]:
            return redirect(url_for("faculty_panel"))
        elif role in ["CENTER_HEAD", "OBSERVER"]:
            return redirect(url_for("exam_center_panel"))
        elif role == "AUDITOR":
            return redirect(url_for("audit_panel"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        mfa_token = request.form.get("mfa_token").strip()

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and user["password"] == password:
            if verify_totp(user["mfa_secret"], mfa_token):
                session["user"] = user["username"]
                session["role"] = user["role"]
                log_audit_event("USER_LOGIN_SUCCESS", user["username"], user["role"], "Logged in with MFA.")
                flash(f"Welcome {user['username']} ({user['role']})", "success")
                return redirect(url_for("dashboard"))
            else:
                log_audit_event("USER_LOGIN_FAILED", username, "UNKNOWN", "Invalid MFA Token.")
                flash("Invalid MFA Code. Use Google Authenticator or demo code: 123456", "danger")
        else:
            log_audit_event("USER_LOGIN_FAILED", username, "UNKNOWN", "Invalid Credentials.")
            flash("Invalid username or password", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    user = session.get("user", "UNKNOWN")
    role = session.get("role", "UNKNOWN")
    log_audit_event("USER_LOGOUT", user, role, "Session terminated.")
    session.clear()
    return redirect(url_for("login"))

# ----------------- MODULE 1: AUTHORING & ENCRYPTION -----------------
@app.route("/faculty", methods=["GET", "POST"])
@login_required(roles=["FACULTY", "REVIEWER"])
def faculty_panel():
    db = get_db()
    if request.method == "POST" and session.get("role") == "FACULTY":
        course_code = request.form.get("course_code")
        title = request.form.get("title")
        content = request.form.get("content")
        exam_start = request.form.get("exam_start")  # e.g., 2026-06-15T09:00
        exam_end = request.form.get("exam_end")

        # Encrypt with AES-256-GCM immediately before storage
        enc_result = encrypt_question_paper(content)

        db.execute(
            """INSERT INTO question_papers 
               (course_code, title, encrypted_data, nonce, exam_start_time, exam_end_time, status, created_by) 
               VALUES (?, ?, ?, ?, ?, ?, 'APPROVED', ?)""",
            (course_code, title, enc_result["ciphertext"], enc_result["nonce"], exam_start, exam_end, session["user"])
        )
        db.commit()

        log_audit_event("PAPER_CREATED_AND_ENCRYPTED", session["user"], session["role"], 
                        f"Paper '{course_code} - {title}' created and encrypted via AES-256-GCM.")
        flash("Question paper encrypted and stored in secure vault!", "success")

    papers = db.execute("SELECT id, course_code, title, exam_start_time, exam_end_time, status, created_by FROM question_papers").fetchall()
    return render_template("faculty.html", papers=papers)

# ----------------- MODULE 3, 4: EXAM CENTER & DUAL CONTROL -----------------
@app.route("/exam-center")
@login_required(roles=["CENTER_HEAD", "OBSERVER"])
def exam_center_panel():
    center_id = "CENTER-DELHI-101"
    db = get_db()
    papers = db.execute("SELECT * FROM question_papers").fetchall()
    
    # Check authorization states
    auth_states = {}
    for p in papers:
        state = db.execute("SELECT * FROM dual_authorizations WHERE paper_id = ? AND center_id = ?", 
                           (p["id"], center_id)).fetchone()
        auth_states[p["id"]] = state

    return render_template("exam_center.html", papers=papers, center_id=center_id, auth_states=auth_states)

@app.route("/exam-center/authorize/<int:paper_id>", methods=["POST"])
@login_required(roles=["CENTER_HEAD", "OBSERVER"])
def dual_authorize(paper_id):
    center_id = "CENTER-DELHI-101"
    role = session.get("role")
    db = get_db()

    row = db.execute("SELECT * FROM dual_authorizations WHERE paper_id = ? AND center_id = ?", 
                     (paper_id, center_id)).fetchone()

    if not row:
        db.execute("INSERT INTO dual_authorizations (paper_id, center_id, superintendent_approved, observer_approved, unlocked) VALUES (?, ?, 0, 0, 0)", 
                   (paper_id, center_id))
        db.commit()

    if role == "CENTER_HEAD":
        db.execute("UPDATE dual_authorizations SET superintendent_approved = 1 WHERE paper_id = ? AND center_id = ?", (paper_id, center_id))
        log_audit_event("DUAL_AUTH_PARTIAL", session["user"], role, f"Superintendent signed approval for Paper #{paper_id}")
    elif role == "OBSERVER":
        db.execute("UPDATE dual_authorizations SET observer_approved = 1 WHERE paper_id = ? AND center_id = ?", (paper_id, center_id))
        log_audit_event("DUAL_AUTH_PARTIAL", session["user"], role, f"Observer signed approval for Paper #{paper_id}")

    db.commit()

    # Check if both have approved
    check = db.execute("SELECT superintendent_approved, observer_approved FROM dual_authorizations WHERE paper_id = ? AND center_id = ?", (paper_id, center_id)).fetchone()
    if check["superintendent_approved"] == 1 and check["observer_approved"] == 1:
        db.execute("UPDATE dual_authorizations SET unlocked = 1 WHERE paper_id = ? AND center_id = ?", (paper_id, center_id))
        db.commit()
        log_audit_event("DUAL_AUTH_COMPLETE", "SYSTEM", "SYSTEM", f"Dual Control passed for Paper #{paper_id}. Decryption unlocked.")
        flash("Dual Authorization Complete! Paper is ready for decryption.", "success")
    else:
        flash("Your approval registered. Awaiting second authority approval.", "info")

    return redirect(url_for("exam_center_panel"))

# ----------------- MODULE 4 & 5: TIME-LOCK DECRYPTION & PRINTING -----------------
@app.route("/exam-center/decrypt/<int:paper_id>")
@login_required(roles=["CENTER_HEAD", "OBSERVER"])
def decrypt_and_view(paper_id):
    center_id = "CENTER-DELHI-101"
    db = get_db()
    paper = db.execute("SELECT * FROM question_papers WHERE id = ?", (paper_id,)).fetchone()
    auth = db.execute("SELECT * FROM dual_authorizations WHERE paper_id = ? AND center_id = ?", (paper_id, center_id)).fetchone()

    # 1. Dual Control Check
    if not auth or auth["unlocked"] != 1:
        log_audit_event("DECRYPTION_BLOCKED", session["user"], session["role"], f"Attempted decryption without Dual Control for Paper #{paper_id}")
        flash("Security Exception: Both authorities must sign before decryption!", "danger")
        return redirect(url_for("exam_center_panel"))

    # 2. Time-Lock Check (Exam Time Window)
    now = datetime.now()
    try:
        start_time = datetime.strptime(paper["exam_start_time"], "%Y-%m-%dT%H:%M")
        end_time = datetime.strptime(paper["exam_end_time"], "%Y-%m-%dT%H:%M")
    except Exception:
        start_time = datetime.strptime(paper["exam_start_time"], "%Y-%m-%d %H:%M")
        end_time = datetime.strptime(paper["exam_end_time"], "%Y-%m-%d %H:%M")

    # Time-lock condition
    if now < start_time:
        diff = start_time - now
        log_audit_event("TIME_LOCK_VIOLATION", session["user"], session["role"], 
                        f"Early decryption attempt on Paper #{paper_id}. Locked for next {diff}.")
        flash(f"Time-Lock Active! Decryption permitted only at exam start: {paper['exam_start_time']}.", "danger")
        return redirect(url_for("exam_center_panel"))

    if now > end_time:
        flash("Exam window has expired for this paper.", "warning")

    # 3. Decrypt payload
    try:
        decrypted_text = decrypt_question_paper(paper["encrypted_data"], paper["nonce"])
        log_audit_event("DECRYPTION_SUCCESS", session["user"], session["role"], f"Paper #{paper_id} decrypted successfully at Exam Center.")
    except Exception as e:
        log_audit_event("DECRYPTION_TAMPER_ALERT", session["user"], session["role"], f"Integrity check failed: {str(e)}")
        flash("Decryption Failed: Tamper or key mismatch detected!", "danger")
        return redirect(url_for("exam_center_panel"))

    return render_template("view_paper.html", paper=paper, content=decrypted_text, center_id=center_id)

@app.route("/exam-center/print/<int:paper_id>")
@login_required(roles=["CENTER_HEAD", "OBSERVER"])
def print_paper(paper_id):
    """Generates and downloads dynamically watermarked PDF for controlled printing."""
    center_id = "CENTER-DELHI-101"
    db = get_db()
    paper = db.execute("SELECT * FROM question_papers WHERE id = ?", (paper_id,)).fetchone()
    decrypted_text = decrypt_question_paper(paper["encrypted_data"], paper["nonce"])

    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf_buffer = generate_watermarked_pdf(
        paper_title=f"{paper['course_code']} - {paper['title']}",
        content=decrypted_text,
        center_id=center_id,
        timestamp=timestamp_str,
        printed_by=session["user"]
    )

    log_audit_event("SECURE_PRINT_GENERATED", session["user"], session["role"], 
                    f"Watermarked PDF printed for center {center_id}.")

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=f"{paper['course_code']}_CONFIDENTIAL_WATERMARKED.pdf",
        mimetype="application/pdf"
    )

# ----------------- MODULE 7: AUDIT & MONITORING SYSTEM -----------------
@app.route("/audit")
@login_required(roles=["AUDITOR"])
def audit_panel():
    db = get_db()
    logs = db.execute("SELECT * FROM audit_logs ORDER BY id DESC").fetchall()
    return render_template("audit.html", logs=logs)

if __name__ == "__main__":
    app.run(debug=True, port=5000)