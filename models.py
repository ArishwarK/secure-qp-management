import sqlite3
from datetime import datetime
from config import DATABASE_PATH

def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # 1. Users table (RBAC + MFA Secret)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL, -- FACULTY, REVIEWER, CENTER_HEAD, OBSERVER, AUDITOR
        mfa_secret TEXT NOT NULL
    )
    """)

    # 2. Encrypted Question Papers Table (Secure Storage)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS question_papers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course_code TEXT NOT NULL,
        title TEXT NOT NULL,
        encrypted_data TEXT NOT NULL,
        nonce TEXT NOT NULL,
        exam_start_time TEXT NOT NULL, -- ISO Format: YYYY-MM-DD HH:MM
        exam_end_time TEXT NOT NULL,
        status TEXT NOT NULL, -- DRAFT, APPROVED, READY
        created_by TEXT NOT NULL
    )
    """)

    # 3. Dual Authorization State Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS dual_authorizations (
        paper_id INTEGER,
        center_id TEXT,
        superintendent_approved INTEGER DEFAULT 0,
        observer_approved INTEGER DEFAULT 0,
        unlocked INTEGER DEFAULT 0,
        PRIMARY KEY (paper_id, center_id)
    )
    """)

    # 4. Audit & Monitoring Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        user TEXT NOT NULL,
        role TEXT NOT NULL,
        details TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        timestamp TEXT NOT NULL
    )
    """)

    # Seed Default Users
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # Default password is 'Admin@123' for demo purposes
        # MFA Base32 secret standard demo key: 'JBSWY3DPEHPK3PXP'
        sample_users = [
            ("prof_smith", "pass123", "FACULTY", "JBSWY3DPEHPK3PXP"),
            ("dean_review", "pass123", "REVIEWER", "JBSWY3DPEHPK3PXP"),
            ("center_head_101", "pass123", "CENTER_HEAD", "JBSWY3DPEHPK3PXP"),
            ("observer_101", "pass123", "OBSERVER", "JBSWY3DPEHPK3PXP"),
            ("auditor_bob", "pass123", "AUDITOR", "JBSWY3DPEHPK3PXP"),
        ]
        cursor.executemany(
            "INSERT INTO users (username, password, role, mfa_secret) VALUES (?, ?, ?, ?)",
            sample_users
        )

    conn.commit()
    conn.close()

def log_audit_event(action: str, user: str, role: str, details: str, ip: str = "127.0.0.1"):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO audit_logs (action, user, role, details, ip_address, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
        (action, user, role, details, ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()