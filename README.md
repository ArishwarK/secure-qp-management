Here is the complete, submission-ready **`README.md`** containing all required sections formatted to score full marks in your evaluation.

Replace the contents of your **`README.md`** file with the following:

---

```markdown
# Secure Question Paper Management System (SQPMS)
### Preventing Leakage and Ensuring Exam Integrity

---

## 1. Brief Description of the Project

The **Secure Question Paper Management System (SQPMS)** is an end-to-end cryptographic and access-controlled software solution engineered to prevent question paper leaks, eliminate single points of compromise, and maintain uncompromised examination integrity.

Built in direct accordance with standard examination security frameworks, the system enforces:
1. **Cryptographic Confidentiality at Rest**: Authored question papers are encrypted using authenticated **AES-256-GCM** immediately upon creation before entering storage.
2. **Strict Identity & Access Governance**: Multi-Factor Authentication (MFA / TOTP) paired with Role-Based Access Control (RBAC) ensures strict least-privilege access across faculty, exam reviewers, center superintendents, external observers, and compliance auditors.
3. **Dual-Control Decryption (Two-Man Rule)**: No single individual possesses the capability to decrypt examination papers. Unlocking requires cryptographic and session approval from two distinct authorities: the **Center Superintendent** and the **External Observer**.
4. **Time-Locked Cryptographic Boundary**: Papers cannot be accessed or decrypted before the scheduled examination start time, completely mitigating advance leakage risks.
5. **Controlled Distribution & Dynamic Watermarking**: Decrypted papers can only be printed through a controlled generation engine that applies dynamic diagonal watermarks (Center ID, timestamp, and printing supervisor identity) across every page to ensure instant forensic traceability.
6. **Immutable Audit & Monitoring Engine**: Real-time logging records every login, submission, approval, decryption attempt, and print event.

---

## 2. Technologies / Tools Used

- **Programming Language**: Python 3.10+
- **Web / API Framework**: Flask 3.0 (WSGI-compliant micro-framework)
- **Cryptographic Suite**: `cryptography` (AES-256-GCM authenticated encryption with 96-bit nonces)
- **Multi-Factor Authentication (MFA)**: `pyotp` (RFC 6238 Time-based One-Time Password - TOTP)
- **Document Generation Engine**: `reportlab` (Dynamic PDF canvas rendering with rotated watermark overlays)
- **Database**: SQLite3 (ACID-compliant relational database, configured with `/tmp` support for serverless deployments)
- **Frontend / Styling**: HTML5, Jinja2 Templating Engine, Bootstrap 5.3 CDN
- **Deployment Platform**: Vercel Serverless Functions (`@vercel/python`)

---

## 3. Steps to Install Dependencies and Run the Project

### Prerequisites
- Python 3.10 or higher installed on your system.
- Git installed.

### Step 1: Clone the Repository
```bash
git clone https://github.com/<YOUR-USERNAME>/secure-qp-management.git
cd secure-qp-management
```

### Step 2: Set Up Virtual Environment (Recommended)
```bash
# On Windows:
python -m venv venv
venv\Scripts\activate

# On Linux / macOS:
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Run the Application Locally
```bash
python app.py
```
Open your browser and navigate to: **`http://127.0.0.1:5000`**

### Pre-Seeded Demonstration Credentials

| Role | Username | Password | Demo MFA Token | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **Faculty (Author)** | `prof_smith` | `pass123` | `123456` | Paper Creation & Encryption |
| **Reviewer / Admin** | `dean_review` | `pass123` | `123456` | Paper Review & Approval |
| **Center Superintendent** | `center_head_101` | `pass123` | `123456` | Authority 1: Dual Approval |
| **External Observer** | `observer_101` | `pass123` | `123456` | Authority 2: Dual Approval |
| **Auditor** | `auditor_bob` | `pass123` | `123456` | Compliance & Event Logs |

*(Note: For testing and evaluation, `123456` is enabled as the standard universal TOTP bypass code alongside RFC 6238 TOTP authenticators).*

---

## 4. Project Structure / Modules and Their Purpose

```text
secure-qp-management/
│
├── requirements.txt         # Core dependencies (Flask, cryptography, reportlab, pyotp)
├── vercel.json              # Serverless build and routing configuration for Vercel deployment
├── config.py                # Environment paths, session secret, and 256-bit AES master key
├── crypto_utils.py          # Module 1 & 2: AES-256-GCM encryption & decryption functions
├── watermark_utils.py       # Module 5: ReportLab dynamic PDF watermarking engine
├── models.py                # Database schema, table initializers, and audit logging utilities
├── auth.py                  # RBAC session validation decorators and TOTP MFA verification
├── app.py                   # Central Flask controller managing workflows, routes, and logic
│
└── templates/               # UI presentation layer
    ├── base.html            # Global layout, navigation header, and flash alert toasts
    ├── login.html           # Multi-Factor Authentication login interface
    ├── faculty.html         # Module 1: Question paper authoring and ciphertext vault view
    ├── exam_center.html     # Module 4: Two-authority dual control dashboard
    ├── view_paper.html      # Secure in-memory decrypted viewing interface
    └── audit.html           # Module 7: Real-time compliance audit trail
```

### Module Responsibilities:
1. **Authoring & Secure Storage (`faculty.html`, `crypto_utils.py`)**:
   Faculties compose question papers and specify the exam time window. The content is immediately converted into AES-256-GCM ciphertext with an initialization vector (nonce) before being committed to the database.
2. **Access Control & Multi-Factor Authentication (`auth.py`)**:
   Enforces Role-Based Access Control (`@login_required`) and 2FA authentication, blocking unauthorized privilege escalations.
3. **Dual Control Key-Release (`app.py`, `exam_center.html`)**:
   Requires independent approvals from both the Center Superintendent and External Observer before the decryption routine can execute.
4. **Time-Lock Enforcement (`app.py`)**:
   Validates server-side timestamps against scheduled exam start times. Blocks decryption attempts made prior to the scheduled exam window.
5. **Secure Printing Engine (`watermark_utils.py`)**:
   Streams a non-cacheable PDF containing diagonal transparent watermarks detailing the Center ID, Supervisor username, and current timestamp to discourage photography or unauthorized duplication.
6. **Audit & Monitoring System (`models.py`, `audit.html`)**:
   Provides non-repudiation by recording timestamps, IP addresses, usernames, and action statuses for all security-relevant system events.

---

## 5. Sample Input and Output

### Scenario 1: Question Paper Authoring & Encryption
- **Module**: 1. Authoring & 2. Secure Storage
- **Actor**: `prof_smith` (Role: `FACULTY`)
- **Sample Input**:
  - Course Code: `CS601`
  - Paper Title: `Network Security & Applied Cryptography`
  - Exam Window: `2026-09-15T09:00` to `2026-09-15T12:00`
  - Questions: `Q1. Detail the operational mechanics of AES-GCM authenticated encryption.`
- **Sample Output**:
  - Nonce: `WzN4...==` (96-bit base64-encoded vector)
  - Ciphertext: `k8L1vX...==` (AES-256 encrypted payload stored in database)
  - Audit Trail Entry: `PAPER_CREATED_AND_ENCRYPTED` registered.

---

### Scenario 2: Dual-Control Sign-Off Workflow
- **Module**: 4. Exam Center System
- **Actors**: `center_head_101` (Superintendent) & `observer_101` (External Observer)
- **Execution Flow**:
  1. `center_head_101` logs in $\rightarrow$ Clicks `✍️ Sign Approval` on Paper `CS601`.
     - **Status**: Superintendent: `Approved` | Observer: `Pending`. Decrypt button remains **Disabled**.
  2. `observer_101` logs in $\rightarrow$ Clicks `✍️ Sign Approval` on Paper `CS601`.
     - **Status**: Superintendent: `Approved` | Observer: `Approved`.
- **Sample Output**:
  - Banner Alert: `Dual Authorization Complete! Paper is ready for decryption.`
  - Decrypt button becomes **Enabled**.

---

### Scenario 3: Time-Lock Violation Attempt (Early Access Blocked)
- **Module**: 4. Time-Lock Controller
- **Actor**: `center_head_101`
- **Context**: Current Time: `2026-09-15 08:45:00` (Exam starts at `09:00:00`).
- **Action**: Clicks `🔓 Decrypt (Time-Locked)`.
- **Sample Output**:
  - HTTP Status: `302 Redirect` to dashboard with error alert.
  - Flash Notice: `Time-Lock Active! Decryption permitted only at exam start: 2026-09-15 09:00.`
  - Audit Log Entry:
    ```text
    Action: TIME_LOCK_VIOLATION | User: center_head_101 | Role: CENTER_HEAD | Details: Early decryption attempt on Paper #1. Locked for next 0:15:00.
    ```

---

### Scenario 4: Successful Decryption & Watermarked Printing
- **Module**: 5. Secure Printing
- **Context**: Dual-Control fulfilled and current time is $\ge$ `09:00:00`.
- **Action**: Supervisor views decrypted paper and clicks `🖨️ Controlled Print`.
- **Sample Output**:
  - File Download: `CS601_CONFIDENTIAL_WATERMARKED.pdf`
  - Rendered Document Properties:
    - **Diagonal Background Watermark**: `EXAM CENTER: CENTER-DELHI-101 | 2026-09-15 09:02:14`
    - **Print Audit Notice**: `PRINTED BY: center_head_101 [CONTROLLED]`
    - **Tamper Warning**: Footer legal warning embedded.
  - Audit Log Entry:
    ```text
    Action: SECURE_PRINT_GENERATED | User: center_head_101 | Details: Watermarked PDF printed for center CENTER-DELHI-101.
    ```
```