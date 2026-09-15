# Secure Question Paper Management System (Preventing Leakage and Ensuring Exam Integrity)

## 1. Brief Description of the Project
The **Secure Question Paper Management System** is a mission-critical examination platform designed to prevent paper leaks and ensure question paper authenticity from creation to printing. 

It implements end-to-end security principles derived from NIST guidelines and Indian higher education examination reforms:
- **AES-256-GCM Cryptographic Storage**: Papers are authored and immediately encrypted with authenticated ciphers before database commitment.
- **Role-Based Access Control (RBAC) & Multi-Factor Authentication (MFA)**: Strictly separates duties across Faculty, Exam Reviewers, Center Superintendents, Observers, and Auditors.
- **Dual-Control Decryption Mechanism**: Decryption key-release requires mutual authorization from two distinct stakeholders (Exam Superintendent + Independent External Observer).
- **Time-Lock Enforcement**: Cryptographic decryption is programmatically barred until the exact synchronized examination commencement window.
- **Secure Watermarked Printing**: Decrypted papers automatically receive a diagonal dynamic watermark containing the Center ID, timestamp, and operator identifier to guarantee traceability.
- **Comprehensive Audit Trail**: Every authentication, approval, decryption, and printing event is persistently logged for forensic audit.

---

## 2. Technologies / Tools Used
- **Backend Framework**: Python 3.10+ / Flask 3.0
- **Cryptography Engine**: `cryptography` (AES-256 in Galois/Counter Mode - GCM)
- **Multi-Factor Authentication**: `pyotp` (RFC 6238 TOTP algorithm)
- **Document Generation**: `reportlab` (Dynamic PDF watermarking & security headers)
- **Database**: SQLite3 (Transactional local datastore)
- **Frontend / Styling**: HTML5, Jinja2, Bootstrap 5.3 CDN

---

## 3. Steps to Install Dependencies and Run the Project

### Step 1: Clone or Extract the Project
```bash
git clone https://github.com/<your-username>/secure-qp-management.git
cd secure-qp-management