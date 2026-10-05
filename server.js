import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import { db } from './db.js';
import { encryptQuestionPaper, decryptQuestionPaper, encryptBuffer, decryptBuffer } from './cryptoUtils.js';
import { verifyTotp, loginRequired } from './authUtils.js';
import { generateWatermarkedPdf, watermarkExistingPdf } from './watermarkUtils.js';

const SECRET_KEY = process.env.SECRET_KEY || 'super-secret-session-key-change-in-production';

function createAuthToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET_KEY).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyAuthToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [data, sig] = token.split('.');
  const expectedSig = crypto.createHmac('sha256', SECRET_KEY).update(data).digest('base64url');
  if (sig !== expectedSig) return null;
  try {
    return JSON.parse(Buffer.from(data, 'base64url').toString('utf-8'));
  } catch {
    return null;
  }
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024 }, // 15MB limit
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;
const HOST = '0.0.0.0';

// Trust proxy for Cloud Run / AI Studio iframe environment
app.set('trust proxy', 1);

// Template engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser(SECRET_KEY));

const sessionMiddleware = session({
  name: 'sqpms.sid',
  secret: SECRET_KEY,
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
  },
});

app.use((req, res, next) => {
  sessionMiddleware(req, res, () => {
    const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
    if (req.session && req.session.cookie) {
      req.session.cookie.secure = isSecure;
      req.session.cookie.sameSite = isSecure ? 'none' : 'lax';
    }

    // Restore session from signed cookie or token if browser blocked 3P session cookie
    const rawToken = req.query._t || req.body?._t || req.cookies?.sqpms_auth;
    const verified = verifyAuthToken(rawToken);
    if (verified && (!req.session.user || req.query._t)) {
      req.session.user = verified.user;
      req.session.role = verified.role;
    }

    const activeToken = req.session?.user
      ? createAuthToken({ user: req.session.user, role: req.session.role })
      : null;

    res.locals.authToken = activeToken || '';

    // Append token on redirects automatically if authenticated so iframe cookie blocking never logs user out
    const origRedirect = res.redirect.bind(res);
    res.redirect = function (url) {
      let targetUrl = url;
      const currentToken = req.session?.user
        ? createAuthToken({ user: req.session.user, role: req.session.role })
        : null;
      if (currentToken && typeof targetUrl === 'string' && targetUrl.startsWith('/') && !targetUrl.startsWith('/logout')) {
        const sep = targetUrl.includes('?') ? '&' : '?';
        targetUrl = `${targetUrl}${sep}_t=${encodeURIComponent(currentToken)}`;
      }
      return origRedirect(targetUrl);
    };

    next();
  });
});

// Flash messages & template context helper
app.use((req, res, next) => {
  res.locals.pendingFlash = [];
  req.flash = (category, text) => {
    if (!req.session.flashMessages) {
      req.session.flashMessages = [];
    }
    req.session.flashMessages.push({ category, text });
    res.locals.pendingFlash.push({ category, text });
  };

  res.locals.messages = req.session.flashMessages || [];
  if (req.query._msg && !res.locals.messages.some((m) => m.text === req.query._msg)) {
    res.locals.messages.push({
      category: req.query._cat || 'info',
      text: req.query._msg,
    });
  }
  req.session.flashMessages = [];
  res.locals.session = req.session;

  const prevRedirect = res.redirect.bind(res);
  res.redirect = function (url) {
    let targetUrl = url;
    if (
      res.locals.pendingFlash &&
      res.locals.pendingFlash.length > 0 &&
      typeof targetUrl === 'string' &&
      targetUrl.startsWith('/') &&
      !targetUrl.includes('_msg=')
    ) {
      const lastMsg = res.locals.pendingFlash[res.locals.pendingFlash.length - 1];
      const sep = targetUrl.includes('?') ? '&' : '?';
      targetUrl = `${targetUrl}${sep}_cat=${encodeURIComponent(lastMsg.category)}&_msg=${encodeURIComponent(lastMsg.text)}`;
    }
    return prevRedirect(targetUrl);
  };

  next();
});

// Helper to get client IP
const getClientIp = (req) => {
  return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || '127.0.0.1';
};

// ----------------- ROOT / DASHBOARD -----------------
app.get('/', (req, res) => {
  if (req.session && req.session.user) {
    const role = req.session.role;
    if (role === 'FACULTY' || role === 'REVIEWER') {
      return res.redirect('/faculty');
    } else if (role === 'CENTER_HEAD' || role === 'OBSERVER') {
      return res.redirect('/exam-center');
    } else if (role === 'AUDITOR') {
      return res.redirect('/audit');
    }
  }
  return res.redirect('/login');
});

// ----------------- AUTHENTICATION & MFA -----------------
app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', (req, res) => {
  const username = (req.body.username || '').trim();
  const password = (req.body.password || '').trim();
  const mfaToken = (req.body.mfa_token || '').trim();
  const clientIp = getClientIp(req);
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';

  const user = db.findUser(username);

  if (user && user.password === password) {
    if (verifyTotp(user.mfa_secret, mfaToken)) {
      req.session.user = user.username;
      req.session.role = user.role;
      const token = createAuthToken({ user: user.username, role: user.role });

      res.cookie('sqpms_auth', token, {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: isSecure,
        sameSite: isSecure ? 'none' : 'lax',
        partitioned: isSecure,
      });

      db.logAuditEvent('USER_LOGIN_SUCCESS', user.username, user.role, 'Logged in with MFA.', clientIp);
      req.flash('success', `Welcome ${user.username} (${user.role})`);
      return req.session.save(() => {
        res.redirect('/');
      });
    } else {
      db.logAuditEvent('USER_LOGIN_FAILED', username, 'UNKNOWN', 'Invalid MFA Token.', clientIp);
      return res.redirect('/login?_cat=danger&_msg=' + encodeURIComponent('Invalid MFA Code. Use Google Authenticator or demo code: 123456'));
    }
  } else {
    db.logAuditEvent('USER_LOGIN_FAILED', username, 'UNKNOWN', 'Invalid Credentials.', clientIp);
    return res.redirect('/login?_cat=danger&_msg=' + encodeURIComponent('Invalid username or password'));
  }
});

app.get('/logout', (req, res) => {
  const user = req.session.user || 'UNKNOWN';
  const role = req.session.role || 'UNKNOWN';
  const clientIp = getClientIp(req);
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';

  res.clearCookie('sqpms_auth', {
    httpOnly: true,
    secure: isSecure,
    sameSite: isSecure ? 'none' : 'lax',
    partitioned: isSecure,
  });

  db.logAuditEvent('USER_LOGOUT', user, role, 'Session terminated.', clientIp);
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// ----------------- MODULE 1: AUTHORING & ENCRYPTION -----------------
app.get('/faculty', loginRequired(['FACULTY', 'REVIEWER']), (req, res) => {
  const papers = db.getQuestionPapers();
  res.render('faculty', { papers });
});

app.post('/faculty', loginRequired(['FACULTY']), upload.single('question_file'), (req, res) => {
  const { course_code, title, content, exam_start, exam_end } = req.body;
  const uploadedFile = req.file;
  const clientIp = getClientIp(req);

  if (!course_code || !title || !exam_start || !exam_end) {
    req.flash('danger', 'Course code, title, and time-lock schedule are required.');
    return res.redirect('/faculty');
  }

  if ((!content || !content.trim()) && !uploadedFile) {
    req.flash('danger', 'Please either type question content or upload a question paper file.');
    return res.redirect('/faculty');
  }

  let finalContent = (content || '').trim();
  let fileEnc = null;
  let fileName = null;
  let fileMime = null;
  let fileSize = null;

  if (uploadedFile) {
    fileName = uploadedFile.originalname;
    fileMime = uploadedFile.mimetype || 'application/octet-stream';
    fileSize = uploadedFile.size;
    fileEnc = encryptBuffer(uploadedFile.buffer);

    // If text-based file (.txt, .md, .csv, .json) and no manual text provided, extract text for inline preview too
    const isTextFile =
      fileMime.startsWith('text/') ||
      /\.(txt|md|csv|json)$/i.test(fileName);

    if (isTextFile && !finalContent) {
      finalContent = uploadedFile.buffer.toString('utf-8');
    } else if (!finalContent) {
      finalContent = `[Attached Encrypted Question Paper File: ${fileName} (${(fileSize / 1024).toFixed(1)} KB)]`;
    }
  }

  // Encrypt with AES-256-GCM immediately before storage
  const encResult = encryptQuestionPaper(finalContent);

  db.addQuestionPaper({
    course_code: course_code.trim(),
    title: title.trim(),
    contentEnc: encResult,
    file_name: fileName,
    file_mime: fileMime,
    file_size: fileSize,
    fileEnc,
    exam_start_time: exam_start,
    exam_end_time: exam_end,
    status: 'APPROVED',
    created_by: req.session.user,
  });

  const fileNote = fileName ? ` (with uploaded file '${fileName}')` : '';
  db.logAuditEvent(
    'PAPER_CREATED_AND_ENCRYPTED',
    req.session.user,
    req.session.role,
    `Paper '${course_code} - ${title}'${fileNote} created and encrypted via AES-256-GCM.`,
    clientIp
  );

  req.flash('success', `Question paper${fileName ? ` and uploaded file (${fileName})` : ''} encrypted and stored in secure vault!`);
  return res.redirect('/faculty');
});

// ----------------- MODULE 3, 4: EXAM CENTER & DUAL CONTROL -----------------
app.get('/exam-center', loginRequired(['CENTER_HEAD', 'OBSERVER']), (req, res) => {
  const centerId = 'CENTER-DELHI-101';
  const papers = db.getQuestionPapers();
  const auth_states = {};

  for (const p of papers) {
    auth_states[p.id] = db.getDualAuth(p.id, centerId);
  }

  res.render('exam_center', { papers, center_id: centerId, auth_states });
});

app.post('/exam-center/authorize/:paperId', loginRequired(['CENTER_HEAD', 'OBSERVER']), (req, res) => {
  const centerId = 'CENTER-DELHI-101';
  const role = req.session.role;
  const paperId = parseInt(req.params.paperId, 10);
  const clientIp = getClientIp(req);

  if (role === 'CENTER_HEAD') {
    db.updateDualAuth(paperId, centerId, { superintendent_approved: 1 });
    db.logAuditEvent('DUAL_AUTH_PARTIAL', req.session.user, role, `Superintendent signed approval for Paper #${paperId}`, clientIp);
  } else if (role === 'OBSERVER') {
    db.updateDualAuth(paperId, centerId, { observer_approved: 1 });
    db.logAuditEvent('DUAL_AUTH_PARTIAL', req.session.user, role, `Observer signed approval for Paper #${paperId}`, clientIp);
  }

  // Check if both have approved
  const check = db.getDualAuth(paperId, centerId);
  if (check.superintendent_approved === 1 && check.observer_approved === 1) {
    db.updateDualAuth(paperId, centerId, { unlocked: 1 });
    db.logAuditEvent('DUAL_AUTH_COMPLETE', 'SYSTEM', 'SYSTEM', `Dual Control passed for Paper #${paperId}. Decryption unlocked.`, clientIp);
    req.flash('success', 'Dual Authorization Complete! Paper is ready for decryption.');
  } else {
    req.flash('info', 'Your approval registered. Awaiting second authority approval.');
  }

  return res.redirect('/exam-center');
});

// ----------------- MODULE 4 & 5: TIME-LOCK DECRYPTION & PRINTING -----------------
app.get('/exam-center/decrypt/:paperId', loginRequired(['CENTER_HEAD', 'OBSERVER']), (req, res) => {
  const centerId = 'CENTER-DELHI-101';
  const paperId = parseInt(req.params.paperId, 10);
  const paper = db.getQuestionPaperById(paperId);
  const clientIp = getClientIp(req);

  if (!paper) {
    req.flash('danger', 'Examination paper not found.');
    return res.redirect('/exam-center');
  }

  const auth = db.getDualAuth(paperId, centerId);

  // 1. Dual Control Check
  if (!auth || auth.unlocked !== 1) {
    db.logAuditEvent(
      'DECRYPTION_BLOCKED',
      req.session.user,
      req.session.role,
      `Attempted decryption without Dual Control for Paper #${paperId}`,
      clientIp
    );
    req.flash('danger', 'Security Exception: Both authorities must sign before decryption!');
    return res.redirect('/exam-center');
  }

  // 2. Time-Lock Check (Exam Time Window)
  const now = new Date();
  const startTime = new Date(paper.exam_start_time);
  const endTime = new Date(paper.exam_end_time);

  if (now < startTime) {
    const diffMs = startTime.getTime() - now.getTime();
    const diffMins = Math.round(diffMs / 60000);
    db.logAuditEvent(
      'TIME_LOCK_VIOLATION',
      req.session.user,
      req.session.role,
      `Early decryption attempt on Paper #${paperId}. Locked for next ${diffMins} minutes.`,
      clientIp
    );
    req.flash('danger', `Time-Lock Active! Decryption permitted only at exam start: ${paper.exam_start_time}.`);
    return res.redirect('/exam-center');
  }

  if (now > endTime) {
    req.flash('warning', 'Exam window has expired for this paper.');
  }

  // 3. Decrypt payload
  try {
    const decryptedText = decryptQuestionPaper(paper.encrypted_data, paper.nonce);
    db.logAuditEvent(
      'DECRYPTION_SUCCESS',
      req.session.user,
      req.session.role,
      `Paper #${paperId} decrypted successfully at Exam Center.`,
      clientIp
    );
    return res.render('view_paper', { paper, content: decryptedText, center_id: centerId });
  } catch (err) {
    db.logAuditEvent(
      'DECRYPTION_TAMPER_ALERT',
      req.session.user,
      req.session.role,
      `Integrity check failed: ${err.message}`,
      clientIp
    );
    req.flash('danger', 'Decryption Failed: Tamper or key mismatch detected!');
    return res.redirect('/exam-center');
  }
});

app.get('/exam-center/print/:paperId', loginRequired(['CENTER_HEAD', 'OBSERVER']), async (req, res) => {
  const centerId = 'CENTER-DELHI-101';
  const paperId = parseInt(req.params.paperId, 10);
  const paper = db.getQuestionPaperById(paperId);
  const clientIp = getClientIp(req);

  if (!paper) {
    return res.status(404).send('Paper not found');
  }

  try {
    const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
    let pdfBuffer;

    if (
      paper.encrypted_file_data &&
      paper.file_nonce &&
      (paper.file_mime === 'application/pdf' || (paper.file_name && paper.file_name.toLowerCase().endsWith('.pdf')))
    ) {
      const rawPdfBuffer = decryptBuffer(paper.encrypted_file_data, paper.file_nonce);
      pdfBuffer = await watermarkExistingPdf({
        pdfBuffer: rawPdfBuffer,
        paperTitle: `${paper.course_code} - ${paper.title}`,
        centerId,
        timestamp,
        printedBy: req.session.user,
      });
    } else {
      const decryptedText = decryptQuestionPaper(paper.encrypted_data, paper.nonce);
      pdfBuffer = await generateWatermarkedPdf({
        paperTitle: `${paper.course_code} - ${paper.title}`,
        content: decryptedText,
        centerId,
        timestamp,
        printedBy: req.session.user,
      });
    }

    db.logAuditEvent(
      'SECURE_PRINT_GENERATED',
      req.session.user,
      req.session.role,
      `Watermarked PDF printed for center ${centerId}.`,
      clientIp
    );

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${paper.course_code}_CONFIDENTIAL_WATERMARKED.pdf"`);
    return res.send(pdfBuffer);
  } catch (err) {
    db.logAuditEvent(
      'PRINT_GENERATION_FAILED',
      req.session.user,
      req.session.role,
      `PDF rendering failure: ${err.message}`,
      clientIp
    );
    req.flash('danger', 'Failed to generate secure PDF document.');
    return res.redirect(`/exam-center/decrypt/${paperId}`);
  }
});

app.get('/exam-center/file/:paperId', loginRequired(['CENTER_HEAD', 'OBSERVER']), async (req, res) => {
  const centerId = 'CENTER-DELHI-101';
  const paperId = parseInt(req.params.paperId, 10);
  const paper = db.getQuestionPaperById(paperId);
  const clientIp = getClientIp(req);

  if (!paper || !paper.encrypted_file_data) {
    req.flash('danger', 'Uploaded question paper file not found.');
    return res.redirect('/exam-center');
  }

  const auth = db.getDualAuth(paperId, centerId);
  if (!auth || auth.unlocked !== 1) {
    req.flash('danger', 'Security Exception: Both authorities must sign before accessing uploaded paper!');
    return res.redirect('/exam-center');
  }

  const now = new Date();
  const startTime = new Date(paper.exam_start_time);
  if (now < startTime) {
    req.flash('danger', `Time-Lock Active! File access permitted only at exam start: ${paper.exam_start_time}.`);
    return res.redirect('/exam-center');
  }

  try {
    let fileBuffer = decryptBuffer(paper.encrypted_file_data, paper.file_nonce);
    const isPdf = paper.file_mime === 'application/pdf' || (paper.file_name && paper.file_name.toLowerCase().endsWith('.pdf'));

    if (isPdf) {
      const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
      fileBuffer = await watermarkExistingPdf({
        pdfBuffer: fileBuffer,
        paperTitle: `${paper.course_code} - ${paper.title}`,
        centerId,
        timestamp,
        printedBy: req.session.user,
      });
    }

    db.logAuditEvent(
      'UPLOADED_FILE_DECRYPTED',
      req.session.user,
      req.session.role,
      `Uploaded file '${paper.file_name}' for Paper #${paperId} decrypted at ${centerId}.`,
      clientIp
    );

    const disposition = req.query.inline === '1' ? 'inline' : 'attachment';
    res.setHeader('Content-Type', paper.file_mime || 'application/octet-stream');
    res.setHeader('Content-Disposition', `${disposition}; filename="${paper.file_name}"`);
    return res.send(fileBuffer);
  } catch (err) {
    db.logAuditEvent(
      'FILE_DECRYPTION_FAILED',
      req.session.user,
      req.session.role,
      `Uploaded file integrity check failed: ${err.message}`,
      clientIp
    );
    req.flash('danger', 'Failed to decrypt uploaded question paper file.');
    return res.redirect(`/exam-center/decrypt/${paperId}`);
  }
});

// ----------------- MODULE 7: AUDIT & MONITORING SYSTEM -----------------
app.get('/audit', loginRequired(['AUDITOR']), (req, res) => {
  const logs = db.getAuditLogs();
  res.render('audit', { logs });
});

// Start dev server when running directly (skip in Vercel serverless functions)
if (!process.env.VERCEL) {
  app.listen(PORT, HOST, () => {
    console.log(`[SQPMS] Server is listening on http://${HOST}:${PORT}`);
  });
}

export default app;

