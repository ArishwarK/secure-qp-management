import { encryptQuestionPaper } from './cryptoUtils.js';

class Database {
  constructor() {
    this.users = [];
    this.questionPapers = [];
    this.dualAuthorizations = new Map(); // key: `${paperId}_${centerId}`
    this.auditLogs = [];
    this.nextPaperId = 1;
    this.nextLogId = 1;

    this.init();
  }

  init() {
    // 1. Seed Users (passwords default to pass123, TOTP demo key JBSWY3DPEHPK3PXP)
    this.users = [
      { id: 1, username: 'prof_smith', password: 'pass123', role: 'FACULTY', mfa_secret: 'JBSWY3DPEHPK3PXP' },
      { id: 2, username: 'dean_review', password: 'pass123', role: 'REVIEWER', mfa_secret: 'JBSWY3DPEHPK3PXP' },
      { id: 3, username: 'center_head_101', password: 'pass123', role: 'CENTER_HEAD', mfa_secret: 'JBSWY3DPEHPK3PXP' },
      { id: 4, username: 'observer_101', password: 'pass123', role: 'OBSERVER', mfa_secret: 'JBSWY3DPEHPK3PXP' },
      { id: 5, username: 'auditor_bob', password: 'pass123', role: 'AUDITOR', mfa_secret: 'JBSWY3DPEHPK3PXP' },
    ];

    // 2. Pre-seed Sample Question Papers
    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
    const twoHoursLater = new Date(now.getTime() + 2 * 60 * 60 * 1000);
    const tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000);
    const tomorrowEnd = new Date(now.getTime() + 27 * 60 * 60 * 1000);

    const formatDt = (d) => d.toISOString().slice(0, 16);

    const content1 = `SECTION A: Cryptographic Foundations (40 Marks)
Q1. Detail the operational mechanics of AES-256-GCM authenticated encryption. Explain how the 96-bit nonce and GMAC authentication tag prevent bit-flipping and chosen-ciphertext attacks. [15 Marks]
Q2. Explain the Two-Man Rule in dual-control key custody architectures. [10 Marks]
Q3. Differentiate between RFC 6238 TOTP and RFC 4226 HOTP in time-sensitive access control systems. [15 Marks]

SECTION B: Forensic Distribution & Auditability (60 Marks)
Q4. Analyze the efficacy of dynamic steganographic diagonal watermarking in preventing physical examination room paper leaks. [20 Marks]
Q5. Design an immutable audit log schema guaranteeing non-repudiation for exam paper release. [20 Marks]`;

    const enc1 = encryptQuestionPaper(content1);
    this.addQuestionPaper({
      course_code: 'CS601',
      title: 'Cryptography & System Security',
      contentEnc: enc1,
      exam_start_time: formatDt(oneHourAgo),
      exam_end_time: formatDt(twoHoursLater),
      status: 'APPROVED',
      created_by: 'prof_smith',
    });

    const content2 = `ADVANCED THREAT HUNTING & PENETRATION TESTING
Q1. Describe kernel-level rootkit detection methodologies. [25 Marks]
Q2. Analyze side-channel timing attacks against AES implementations without constant-time execution. [25 Marks]`;

    const enc2 = encryptQuestionPaper(content2);
    this.addQuestionPaper({
      course_code: 'CYBER702',
      title: 'Advanced Threat Hunting',
      contentEnc: enc2,
      exam_start_time: formatDt(tomorrow),
      exam_end_time: formatDt(tomorrowEnd),
      status: 'APPROVED',
      created_by: 'prof_smith',
    });

    // Seed initial audit log
    this.logAuditEvent('SYSTEM_INITIALIZATION', 'SYSTEM', 'SYSTEM', 'In-memory cryptographic database and RBAC schemas initialized.');
  }

  findUser(username) {
    return this.users.find((u) => u.username === username.trim());
  }

  getQuestionPapers() {
    return this.questionPapers;
  }

  getQuestionPaperById(id) {
    const numId = parseInt(id, 10);
    return this.questionPapers.find((p) => p.id === numId);
  }

  addQuestionPaper({
    course_code,
    title,
    contentEnc,
    exam_start_time,
    exam_end_time,
    status,
    created_by,
    file_name = null,
    file_mime = null,
    file_size = null,
    fileEnc = null,
  }) {
    const paper = {
      id: this.nextPaperId++,
      course_code,
      title,
      encrypted_data: contentEnc.ciphertext,
      nonce: contentEnc.nonce,
      file_name,
      file_mime,
      file_size,
      encrypted_file_data: fileEnc ? fileEnc.ciphertext : null,
      file_nonce: fileEnc ? fileEnc.nonce : null,
      exam_start_time,
      exam_end_time,
      status: status || 'APPROVED',
      created_by,
    };
    this.questionPapers.push(paper);

    // Initialize dual auth record for standard center
    const centerId = 'CENTER-DELHI-101';
    const key = `${paper.id}_${centerId}`;
    this.dualAuthorizations.set(key, {
      paper_id: paper.id,
      center_id: centerId,
      superintendent_approved: 0,
      observer_approved: 0,
      unlocked: 0,
    });

    return paper;
  }

  getDualAuth(paperId, centerId = 'CENTER-DELHI-101') {
    const key = `${paperId}_${centerId}`;
    if (!this.dualAuthorizations.has(key)) {
      this.dualAuthorizations.set(key, {
        paper_id: parseInt(paperId, 10),
        center_id: centerId,
        superintendent_approved: 0,
        observer_approved: 0,
        unlocked: 0,
      });
    }
    return this.dualAuthorizations.get(key);
  }

  updateDualAuth(paperId, centerId = 'CENTER-DELHI-101', updates = {}) {
    const record = this.getDualAuth(paperId, centerId);
    Object.assign(record, updates);
    return record;
  }

  logAuditEvent(action, user, role, details, ip = '127.0.0.1') {
    const now = new Date();
    const timestamp = now.toISOString().replace('T', ' ').slice(0, 19);
    const log = {
      id: this.nextLogId++,
      action,
      user,
      role,
      details,
      ip_address: ip,
      timestamp,
    };
    this.auditLogs.unshift(log); // newest first
    return log;
  }

  getAuditLogs() {
    return this.auditLogs;
  }
}

export const db = new Database();
