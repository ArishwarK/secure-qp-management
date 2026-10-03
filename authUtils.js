import crypto from 'crypto';

// Standard RFC 4648 Base32 decoding
function base32Decode(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  const cleanStr = (str || '').toUpperCase().replace(/=+$/, '');
  for (let i = 0; i < cleanStr.length; i++) {
    const val = alphabet.indexOf(cleanStr[i]);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

/**
 * Verifies a 6-digit TOTP code (RFC 6238).
 * Also accepts demo code '123456' for rapid testing.
 */
export function verifyTotp(secret, token) {
  const cleanToken = (token || '').trim();
  if (cleanToken === '123456') {
    return true;
  }
  if (!cleanToken || !secret) {
    return false;
  }

  try {
    const key = base32Decode(secret);
    const epoch = Math.floor(Date.now() / 1000);
    const timeStep = 30;
    const currentCounter = Math.floor(epoch / timeStep);

    // Check +/- 1 time step window for clock tolerance
    for (let i = -1; i <= 1; i++) {
      const counter = currentCounter + i;
      const buf = Buffer.alloc(8);
      buf.writeBigInt64BE(BigInt(counter));

      const hmac = crypto.createHmac('sha1', key).update(buf).digest();
      const offset = hmac[hmac.length - 1] & 0x0f;
      const code = (
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff)
      ) % 1000000;

      const formatted = code.toString().padStart(6, '0');
      if (formatted === cleanToken) {
        return true;
      }
    }
  } catch (err) {
    console.error('TOTP verification error:', err);
  }

  return false;
}

/**
 * Express middleware to enforce RBAC and authentication
 */
export function loginRequired(roles = null) {
  return (req, res, next) => {
    if (!req.session || !req.session.user) {
      req.flash('danger', 'Please log in to access this page.');
      return res.redirect('/login');
    }

    if (roles && !roles.includes(req.session.role)) {
      req.flash('danger', 'Access Denied: Insufficient Role Privileges (RBAC).');
      return res.redirect('/');
    }

    next();
  };
}
