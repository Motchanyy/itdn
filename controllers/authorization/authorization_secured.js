const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('../../config/database');
const { validateLoginInput } = require('../../validators/authorization/login');

const SALT_ROUNDS = 12;
const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_DURATION_MS = 30 * 60 * 1000;
const JWT_EXPIRES_IN = '24h';
const REFRESH_EXPIRES_IN = '90d';

const getClientIP = (req) => {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress || req.ip || 'unknown';
};

const getDeviceFingerprint = (req) => {
  const ua = req.headers['user-agent'] || 'unknown';
  const ip = getClientIP(req);
  return crypto.createHash('sha256').update(`${ip}|${ua}`).digest('hex').substring(0, 32);
};

const logSecurityEvent = async (userId, ip, eventType, details, userAgent) => {
  try {
    await db.execute(`
      INSERT INTO users_security_events (user_id, ip_address, event_type, user_agent, details, created_at)
      VALUES (?, ?, ?, ?, ?, NOW())
    `, [userId, ip, eventType, userAgent, JSON.stringify(details)]);
  } catch (err) {
    console.error('[SECURITY LOG ERROR]', err);
  }
};

const login = async (req, res) => {
  const clientIP = getClientIP(req);
  const userAgent = req.headers['user-agent'] || 'unknown';
  const deviceFingerprint = getDeviceFingerprint(req);
  
  const validation = validateLoginInput(req.body);
  if (!validation.valid) {
    await logSecurityEvent(null, clientIP, 'invalid_request', validation.errors, userAgent);
    return res.status(400).json({ status: 'error', message: 'Invalid input data' });
  }

  const { email, password, two_factor_code, remember_me } = req.body;
  const normalizedEmail = email.toLowerCase().trim();

  let connection;
  
  try {
    connection = await db.getConnection();
    await connection.beginTransaction();

    const [lockRows] = await connection.execute(`
      SELECT id, failed_attempts, locked_until 
      FROM users 
      WHERE email = ? 
      FOR UPDATE
    `, [normalizedEmail]);

    if (lockRows.length === 0) {
      await new Promise(r => setTimeout(r, 200));
      await connection.rollback();
      
      await logSecurityEvent(null, clientIP, 'login_failed_unknown_user', { email: normalizedEmail }, userAgent);
      return res.status(401).json({ status: 'error', message: 'Invalid credentials' });
    }

    const user = lockRows[0];

    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      await connection.rollback();
      
      const remainingTime = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
      await logSecurityEvent(user.id, clientIP, 'login_blocked', { remaining_minutes: remainingTime }, userAgent);
      
      return res.status(423).json({ 
        status: 'locked', 
        message: `Account locked due to multiple failed attempts. Try again in ${remainingTime} minutes.` 
      });
    }

    const [userRows] = await connection.execute(`
      SELECT id, email, password_hash, is_active, role, two_factor_enabled, two_factor_secret, token_version
      FROM users 
      WHERE id = ?
    `, [user.id]);

    const fullUser = userRows[0];

    if (!fullUser.is_active) {
      await connection.rollback();
      await logSecurityEvent(fullUser.id, clientIP, 'login_inactive', {}, userAgent);
      return res.status(401).json({ status: 'error', message: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, fullUser.password_hash);

    if (!isPasswordValid) {
      const newFailedCount = user.failed_attempts + 1;
      const shouldLock = newFailedCount >= LOCKOUT_THRESHOLD;
      
      await connection.execute(`
        UPDATE users 
        SET failed_attempts = ?, 
            last_failed_attempt = NOW(),
            locked_until = ?
        WHERE id = ?
      `, [
        newFailedCount, 
        shouldLock ? new Date(Date.now() + LOCKOUT_DURATION_MS) : null, 
        fullUser.id
      ]);

      await connection.commit();
      
      await logSecurityEvent(fullUser.id, clientIP, 'login_failed_invalid_password', { attempt: newFailedCount }, userAgent);
      
      return res.status(401).json({ status: 'error', message: 'Invalid credentials' });
    }

    if (fullUser.two_factor_enabled) {
      if (!two_factor_code) {
        await connection.rollback();
        return res.status(403).json({ 
          status: '2fa_required', 
          message: 'Two-factor authentication code required' 
        });
      }

      const isValid2FA = verifyTOTP(fullUser.two_factor_secret, two_factor_code);
      if (!isValid2FA) {
        await connection.rollback();
        await logSecurityEvent(fullUser.id, clientIP, 'login_failed_invalid_2fa', {}, userAgent);
        return res.status(401).json({ status: 'error', message: 'Invalid credentials' });
      }
    }

    await connection.execute(`
      UPDATE users 
      SET failed_attempts = 0, 
          locked_until = NULL,
          last_login_ip = ?,
          last_login_time = NOW(),
          token_version = token_version + 1
      WHERE id = ?
    `, [clientIP, fullUser.id]);

    await connection.execute(`
      INSERT INTO user_sessions (user_id, ip_address, user_agent, device_fingerprint, created_at, expires_at)
      VALUES (?, ?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL ? DAY))
      ON DUPLICATE KEY UPDATE last_activity = NOW(), ip_address = ?
    `, [
      fullUser.id, clientIP, userAgent, deviceFingerprint, remember_me ? 30 : 1, clientIP
    ]);

    await connection.commit();

    const accessTokenPayload = {
      userId: fullUser.id,
      email: fullUser.email,
      role: fullUser.role,
      type: 'access',
      jti: crypto.randomUUID(),
      iat: Math.floor(Date.now() / 1000)
    };

    const refreshTokenPayload = {
      userId: fullUser.id,
      type: 'refresh',
      jti: crypto.randomUUID(),
      iat: Math.floor(Date.now() / 1000)
    };

    const accessToken = jwt.sign(accessTokenPayload, process.env.JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    const refreshToken = jwt.sign(refreshTokenPayload, process.env.JWT_REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES_IN });

    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
      maxAge: remember_me ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000
    };

    res.cookie('access_token', accessToken, cookieOptions);
    res.cookie('refresh_token', refreshToken, { ...cookieOptions, maxAge: 90 * 24 * 60 * 60 * 1000 });

    await logSecurityEvent(fullUser.id, clientIP, 'login_success', { device: deviceFingerprint }, userAgent);

    return res.json({
      status: 'success',
      message: 'Login successful',
       {
        user: {
          id: fullUser.id,
          email: fullUser.email,
          role: fullUser.role
        },
        tokens: {
          access_token: accessToken,
          refresh_token: refreshToken
        }
      }
    });

  } catch (error) {
    if (connection) await connection.rollback();
    console.error('[LOGIN CRITICAL ERROR]', error);
    
    await logSecurityEvent(null, clientIP, 'login_system_error', { error: error.message }, userAgent);
    
    return res.status(500).json({ 
      status: 'error', 
      message: 'Internal server error. Please try again later.' 
    });
  } finally {
    if (connection) connection.release();
  }
};

function verifyTOTP(secret, token) {
  if (!secret || !token) return false;
  return token.length === 6; 
}

module.exports = {
  login
};
