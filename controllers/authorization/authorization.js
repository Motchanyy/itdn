"use strict";

const jwt = require("jsonwebtoken");
const bcryptjs = require("bcryptjs");
const { promisify } = require("util");
const validator = require("validator");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

// ─── Валідація AJV ───────────────────────────────────────────────────────────
const validateLogin = require("../../validators/authorization/login");

// ─── Конфігурація ────────────────────────────────────────────────────────────
const config = require("../../config/config");
const configDatabase = config.get("configDatabase");
const jwtConfig = config.get("configJWT");

// ─── Логування ───────────────────────────────────────────────────────────────
const logging = require("../../logging/logging");

// ─── БД ──────────────────────────────────────────────────────────────────────
const connection_pool = require("../../config/database/connection_pool");

// ─── 2FA ─────────────────────────────────────────────────────────────────────
const tfa = require("../../helpers/tfa");

// ─── Кеш ─────────────────────────────────────────────────────────────────────
const NodeCache = require("node-cache");
const userCache = new NodeCache({
  stdTTL: 60,
  checkperiod: 120,
  maxKeys: 5000,
});

// ─── Константи ───────────────────────────────────────────────────────────────
const DB_PREFIX = configDatabase.prefix;
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_DURATION_MIN = 15;
const BCRYPT_ROUNDS = 12;
const TFA_MAX_ATTEMPTS = 5;
const TFA_LOCK_MIN = 15;
const TFA_CHALLENGE_TTL_SEC = 300; // 5 хв на введення коду

// ─── Rate limiters (ПОСИЛЕНІ) ────────────────────────────────────────────────
// Глобальне обмеження по IP для запобігання brute-force атакам

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 хвилин
  max: 5, // Тільки 5 спроб на IP
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getClientIp(req),
  handler: (req, res) =>
    res.status(429).json({
      status: "rate_limited",
      errors: [{ field: "rate", minutes: 15 }],
    }),
  skipSuccessfulRequests: false, // Рахувати навіть успішні запити
  message: "Занадто багато спроб входу, будь ласка, спробуйте пізніше",
});

const tfaLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 хвилин
  max: 3, // Тільки 3 спроби 2FA на IP
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getClientIp(req),
  handler: (req, res) =>
    res.status(429).json({
      status: "rate_limited",
      errors: [{ field: "rate", minutes: 15 }],
    }),
  skipSuccessfulRequests: false,
});

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Отримання IP адреси клієнта з урахуванням проксі
 * Обрізаємо до 45 символів для IPv6
 */
function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  const ip = forwarded ? forwarded.split(",")[0].trim() : req.socket?.remoteAddress || "";
  return ip.substring(0, 45);
}

/**
 * Визначення типу пристрою за User-Agent
 * 0 = Desktop, 1 = Mobile, 2 = Tablet
 */
function detectDevice(userAgent = "") {
  const ua = userAgent.toLowerCase();
  if (/tablet|ipad|playbook|silk/.test(ua)) return 2;
  if (/mobile|android|iphone|ipod|blackberry|opera mini|iemobile/.test(ua)) return 1;
  return 0;
}

/**
 * Запис логіну в БД з розширеною інформацією
 */
function writeLoginLog(userId, req, success) {
  const ip = getClientIp(req);
  const userAgent = (req.headers["user-agent"] || "").substring(0, 512);
  const device = detectDevice(userAgent);

  connection_pool
    .query(
      `INSERT INTO \`${DB_PREFIX}users_login_log\`
             (id_user, ip, user_agent, device, status)
             VALUES (?, ?, ?, ?, ?)`,
      [userId, ip, userAgent, device, success ? 1 : 0]
    )
    .catch((err) => logging.error("[writeLoginLog]", err));
}

/**
 * Логування подій безпеки (підозріла активність, зміна IP тощо)
 */
async function logSecurityEvent(userId, eventType, req, extraData = {}) {
  const ip = getClientIp(req);
  const userAgent = (req.headers["user-agent"] || "").substring(0, 512);
  
  try {
    await connection_pool.query(
      `INSERT INTO \`${DB_PREFIX}users_security_events\`
             (id_user, event_type, ip, user_agent, extra_data)
             VALUES (?, ?, ?, ?, ?)`,
      [userId, eventType, ip, userAgent, JSON.stringify(extraData)]
    );
  } catch (err) {
    logging.error("[logSecurityEvent]", err);
  }
}

async function loadUserPermissions(userId) {
  const [rows] = await connection_pool.query(
    `SELECT pp.slug,
                MAX(gp.can_view)   AS can_view,
                MAX(gp.can_add)    AS can_add,
                MAX(gp.can_edit)   AS can_edit,
                MAX(gp.can_delete) AS can_delete
         FROM \`${DB_PREFIX}users_to_groups\` ug
         INNER JOIN \`${DB_PREFIX}users_groups_permissions\` gp ON gp.id_group = ug.id_group
         INNER JOIN \`${DB_PREFIX}users_permissions_pages\`  pp ON pp.id       = gp.id_page
         WHERE ug.id_user = ?
         GROUP BY pp.slug`,
    [userId]
  );

  const permissions = {};
  for (const row of rows) {
    permissions[row.slug] = {
      view: row.can_view === 1,
      add: row.can_add === 1,
      edit: row.can_edit === 1,
      delete: row.can_delete === 1,
    };
  }
  return permissions;
}

function hasPermission(req, slug, action = "view") {
  return req.user?.permissions?.[slug]?.[action] === true;
}

exports.hasPermission = hasPermission;

function invalidateUserCache(userId) {
  userCache.del(`user_${userId}`);
}

// ─── 2FA challenge ───────────────────────────────────────────────────────────

/**
 * Проміжний токен між "пароль вірний" і "код введено".
 * Окремий secret + окремий cookie, щоб його не можна було
 * підсунути замість повноцінного login-токена.
 */
function signTfaChallenge(userId, tokenVersion, rememberMe) {
  return jwt.sign(
    {
      id: userId,
      tv: tokenVersion,
      rm: rememberMe === true,
      purpose: "tfa",
      jti: crypto.randomBytes(16).toString("hex"),
    },
    jwtConfig.jwt.jwt_secret + "|tfa",
    { expiresIn: TFA_CHALLENGE_TTL_SEC }
  );
}

async function verifyTfaChallenge(token) {
  if (!token) return null;
  try {
    const decoded = await promisify(jwt.verify)(token, jwtConfig.jwt.jwt_secret + "|tfa");
    if (decoded.purpose !== "tfa") return null;
    return decoded;
  } catch {
    return null;
  }
}

function setTfaChallengeCookie(res, token) {
  const isProd = process.env.NODE_ENV === "production";
  res.cookie("tfa_challenge", token, {
    maxAge: TFA_CHALLENGE_TTL_SEC * 1000,
    httpOnly: true,
    secure: isProd,
    sameSite: "strict", // ПОСИЛЕНО: strict для захисту від CSRF
    path: "/"
  });
}

/**
 * Видача фінального login-cookie. Винесено окремо,
 * бо викликається з двох місць: login (без 2FA) і tfa_verify.
 */
function issueLoginCookie(res, user, remember_me) {
  const expiresIn = remember_me && jwtConfig.jwt.jwt_time_expires_remember ? jwtConfig.jwt.jwt_time_expires_remember : jwtConfig.jwt.jwt_time_expires;

  const token = jwt.sign({ id: user.id, tv: user.token_version }, jwtConfig.jwt.jwt_secret, { expiresIn });

  const isProd = process.env.NODE_ENV === "production";

  res.cookie("login", token, {
    expires: new Date(Date.now() + Number(jwtConfig.jwt.jwt_cookie_expiring) * 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure: isProd,
    sameSite: "strict", // ПОСИЛЕНО: strict для захисту від CSRF
    path: "/"
  });
}

// ─── Register ────────────────────────────────────────────────────────────────

exports.register = async (req, res) => {
  try {
    const first_name = (req.body.first_name || "").trim().replace(/\s{2,}/g, " ");
    const last_name = (req.body.last_name || "").trim().replace(/\s{2,}/g, " ");
    const patronymic = (req.body.patronymic || "").trim().replace(/\s{2,}/g, " ");
    const email = (req.body.email || "").trim().toLowerCase();
    const password = (req.body.password || "").trim();

    const errors = [];

    if (!first_name || validator.isEmpty(first_name)) {
      errors.push({ field: "first_name", msg: res.__("please_fill_out_this_field") });
    }
    if (!last_name || validator.isEmpty(last_name)) {
      errors.push({ field: "last_name", msg: res.__("please_fill_out_this_field") });
    }
    if (!email || !validator.isEmail(email)) {
      errors.push({ field: "email", msg: res.__("please_fill_out_this_field") });
    }
    if (!password || validator.isEmpty(password)) {
      errors.push({ field: "password", msg: res.__("please_fill_out_this_field") });
    } else if (!validator.isLength(password, { min: 8 })) {
      errors.push({ field: "password", msg: res.__("password_min_length") });
    }

    if (errors.length > 0) {
      return res.status(422).json({ status: "error", errors });
    }

    const [[existingUser]] = await connection_pool.query(`SELECT id FROM \`${DB_PREFIX}users\` WHERE email = ? LIMIT 1`, [email]);

    if (existingUser) {
      return res.status(409).json({
        status: "error",
        errors: [{ field: "email", msg: res.__("email_exists") }],
      });
    }

    const passwordHash = await bcryptjs.hash(password, BCRYPT_ROUNDS);

    await connection_pool.query(
      `INSERT INTO \`${DB_PREFIX}users\`
             (first_name, last_name, patronymic, email, password)
             VALUES (?, ?, ?, ?, ?)`,
      [first_name, last_name, patronymic, email, passwordHash]
    );

    return res.status(201).json({ status: "success" });
  } catch (error) {
    logging.error("[register]", error);
    return res.status(500).json({ status: "error" });
  }
};

// ─── Login (МАКСИМАЛЬНИЙ ЗАХИСТ) ─────────────────────────────────────────────

exports.login = async (req, res) => {
  try {
    // КРОК 1: Валідація вхідних даних через AJV
    const validationErrors = validateLogin(req.body);
    
    if (validationErrors) {
      // Форматуємо помилки AJV у зручний вигляд
      const errors = validationErrors.map(err => {
        let field = err.instancePath.substring(1) || "data";
        let msg = res.__("please_fill_out_this_field");
        
        if (err.keyword === "format" && err.params.format === "email") {
          msg = res.__("invalid_email_format");
        } else if (err.keyword === "minLength" && err.params.missingProperty) {
          msg = res.__("field_required");
        } else if (err.keyword === "pattern") {
          if (err.instancePath.includes("email")) {
            msg = res.__("invalid_email_format");
          } else if (err.instancePath.includes("tfa_code")) {
            msg = res.__("invalid_2fa_code_format");
          }
        } else if (err.keyword === "additionalProperties") {
          msg = res.__("unexpected_field");
        }
        
        return { field, msg };
      });
      
      logging.warn(`[login] Validation failed from IP ${getClientIp(req)}`, { 
        errors: validationErrors,
        body: req.body 
      });
      
      return res.status(422).json({ status: "error", errors });
    }
    
    // КРОК 2: Санітизація даних (додатковий захист)
    const email = req.body.email.trim().toLowerCase();
    const password = req.body.password.trim();
    const remember_me = req.body.remember_me === true;
    const tfa_code = req.body.tfa_code?.trim();
    
    // КРОК 3: Перевірка на наявність користувача
    const [[user]] = await connection_pool.query(
      `SELECT id, email, password, active,
                    failed_login_attempts, locked_until,
                    tfa_enabled, tfa_secret, token_version,
                    last_login_ip, last_device_type
             FROM \`${DB_PREFIX}users\`
             WHERE email = ? LIMIT 1`,
      [email]
    );

    // Універсальна відповідь для запобігання enumeration attacks
    const genericAuthError = () => res.status(401).json({
      status: "invalid",
      errors: [{ field: "invalid" }],
    });

    if (!user) {
      logging.info(`[login] Failed login attempt for non-existent user: ${email} from IP ${getClientIp(req)}`);
      return genericAuthError();
    }

    // КРОК 4: Перевірка блокування акаунту
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      const minutesLeft = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
      logging.warn(`[login] Account locked: ${user.id} from IP ${getClientIp(req)}, locked until: ${user.locked_until}`);
      
      return res.status(429).json({
        status: "locked",
        errors: [{ field: "locked", minutes: minutesLeft }],
      });
    }

    // КРОК 5: Перевірка паролю з constant-time comparison
    let passwordMatch;
    try {
      passwordMatch = await bcryptjs.compare(password, user.password);
    } catch (err) {
      logging.error("[login] bcrypt compare error", err);
      return res.status(500).json({ status: "error" });
    }

    if (!passwordMatch) {
      // Збільшуємо лічильник невдалих спроб
      const newAttempts = (user.failed_login_attempts || 0) + 1;
      const shouldLock = newAttempts >= MAX_FAILED_ATTEMPTS;
      const lockedUntil = shouldLock 
        ? new Date(Date.now() + LOCK_DURATION_MIN * 60 * 1000) 
        : null;

      await connection_pool.query(
        `UPDATE \`${DB_PREFIX}users\`
         SET failed_login_attempts = ?, locked_until = ?
         WHERE id = ?`,
        [newAttempts, lockedUntil, user.id]
      );

      writeLoginLog(user.id, req, false);
      
      // Логуємо підозрілу активність після кількох невдалих спроб
      if (newAttempts >= 3) {
        await logSecurityEvent(user.id, "login_failed_multiple", req, {
          attempts: newAttempts,
          email: email
        });
      }

      logging.warn(`[login] Invalid password for user ${user.id}, attempt ${newAttempts}, IP: ${getClientIp(req)}`);
      
      return genericAuthError();
    }

    // КРОК 6: Перевірка активності акаунту
    if (user.active !== 1) {
      logging.warn(`[login] Inactive account tried to login: ${user.id}, IP: ${getClientIp(req)}`);
      return res.status(403).json({
        status: "invalid",
        errors: [{ field: "account_not_active" }],
      });
    }

    // КРОК 7: Скидання лічильника невдалих спроб після успішної перевірки паролю
    await connection_pool.query(
      `UPDATE \`${DB_PREFIX}users\`
       SET failed_login_attempts = 0, locked_until = NULL
       WHERE id = ?`,
      [user.id]
    );

    // КРОК 8: Перевірка на новий пристрій/IP (підозріла активність)
    const currentIp = getClientIp(req);
    const currentDevice = detectDevice(req.headers["user-agent"] || "");
    
    const isNewDevice = user.last_device_type !== currentDevice;
    const isNewIp = user.last_login_ip !== currentIp;
    
    if (isNewDevice || isNewIp) {
      await logSecurityEvent(user.id, "login_new_device_or_ip", req, {
        current_ip: currentIp,
        previous_ip: user.last_login_ip,
        current_device: currentDevice,
        previous_device: user.last_device_type,
        is_new_device: isNewDevice,
        is_new_ip: isNewIp
      });
      
      logging.info(`[login] New device/IP detected for user ${user.id}: IP=${currentIp}, Device=${currentDevice}`);
    }

    // КРОК 9: 2FA перевірка
    if (user.tfa_enabled === 1 && user.tfa_secret) {
      const challenge = signTfaChallenge(user.id, user.token_version, remember_me);
      setTfaChallengeCookie(res, challenge);

      logging.info(`[login] 2FA required for user ${user.id}, IP: ${currentIp}`);
      return res.json({ status: "tfa_required" });
    }

    // КРОК 10: Успішний логін - оновлення останнього входу
    await connection_pool.query(
      `UPDATE \`${DB_PREFIX}users\`
       SET date_last_login = NOW(),
           last_login_ip = ?,
           last_device_type = ?
       WHERE id = ?`,
      [currentIp, currentDevice, user.id]
    );

    writeLoginLog(user.id, req, true);
    invalidateUserCache(user.id);

    issueLoginCookie(res, user, remember_me);

    logging.info(`[login] Successful login for user ${user.id}, IP: ${currentIp}, Device: ${currentDevice}`);

    return res.json({ status: "success", url: "/" });
    
  } catch (error) {
    logging.error("[login] Critical error", error);
    return res.status(500).json({ status: "error" });
  }
};

// ─── 2FA: перевірка коду ─────────────────────────────────────────────────────

exports.tfa_verify = async (req, res) => {
  try {
    const decoded = await verifyTfaChallenge(req.cookies.tfa_challenge);

    if (!decoded) {
      res.clearCookie("tfa_challenge");
      return res.status(401).json({
        status: "challenge_expired",
        errors: [{ field: "challenge" }],
      });
    }

    const code = tfa.normalizeCode(req.body.code);
    const useBackup = req.body.backup === true || req.body.backup === "true";
    const remember_me = decoded.rm === true;

    const formatOk = useBackup ? tfa.isValidBackupFormat(code) : tfa.isValidCodeFormat(code);

    if (!formatOk) {
      return res.status(422).json({
        status: "error",
        errors: [{ field: "code", msg: res.__("please_fill_out_this_field") }],
      });
    }

    const [[user]] = await connection_pool.query(
      `SELECT id, email, active, token_version,
                    tfa_enabled, tfa_secret, tfa_last_step,
                    tfa_failed_attempts, tfa_locked_until
             FROM \`${DB_PREFIX}users\`
             WHERE id = ? LIMIT 1`,
      [decoded.id]
    );

    if (!user || user.active !== 1 || user.tfa_enabled !== 1) {
      res.clearCookie("tfa_challenge");
      return res.status(401).json({
        status: "challenge_expired",
        errors: [{ field: "challenge" }],
      });
    }

    // token_version змінився (logout/зміна пароля) → challenge недійсний
    if (decoded.tv !== user.token_version) {
      res.clearCookie("tfa_challenge");
      return res.status(401).json({
        status: "challenge_expired",
        errors: [{ field: "challenge" }],
      });
    }

    // Лок за перебір кодів
    if (user.tfa_locked_until && new Date(user.tfa_locked_until) > new Date()) {
      const minutesLeft = Math.ceil((new Date(user.tfa_locked_until) - new Date()) / 60000);
      return res.status(429).json({
        status: "locked",
        errors: [{ field: "locked", minutes: minutesLeft }],
      });
    }

    let verified = false;
    let usedStep = null;

    if (useBackup) {
      // Атомарне погашення: гонка неможлива
      const [result] = await connection_pool.query(
        `UPDATE \`${DB_PREFIX}users_tfa_backup_codes\`
                 SET used_at = NOW()
                 WHERE id_user = ? AND code_hash = ? AND used_at IS NULL`,
        [user.id, tfa.hashBackupCode(code)]
      );
      verified = result.affectedRows === 1;
    } else {
      const result = tfa.verifyTotp(user.tfa_secret, code, user.tfa_last_step);
      verified = result.ok;
      usedStep = result.step;
    }

    if (!verified) {
      const attempts = (user.tfa_failed_attempts || 0) + 1;
      const lockedUntil = attempts >= TFA_MAX_ATTEMPTS ? new Date(Date.now() + TFA_LOCK_MIN * 60 * 1000) : null;

      await connection_pool.query(
        `UPDATE \`${DB_PREFIX}users\`
                 SET tfa_failed_attempts = ?,
                     tfa_locked_until    = ?
                 WHERE id = ?`,
        [attempts, lockedUntil, user.id]
      );

      writeLoginLog(user.id, req, false);

      if (lockedUntil) {
        res.clearCookie("tfa_challenge");
        return res.status(429).json({
          status: "locked",
          errors: [{ field: "locked", minutes: TFA_LOCK_MIN }],
        });
      }

      return res.status(401).json({
        status: "invalid",
        errors: [{ field: "code" }],
      });
    }

    // ── Успіх ────────────────────────────────────────────────────────────
    // tfa_last_step оновлюємо з умовою > поточного: захист від
    // паралельних запитів, що намагаються "відкотити" крок назад.
    await connection_pool.query(
      `UPDATE \`${DB_PREFIX}users\`
             SET tfa_failed_attempts = 0,
                 tfa_locked_until    = NULL,
                 tfa_last_step       = GREATEST(tfa_last_step, ?),
                 date_last_login     = NOW()
             WHERE id = ?`,
      [usedStep || 0, user.id]
    );

    writeLoginLog(user.id, req, true);
    invalidateUserCache(user.id);

    res.clearCookie("tfa_challenge");
    issueLoginCookie(res, user, remember_me);

    return res.json({ status: "success", url: "/" });
  } catch (error) {
    logging.error("[tfa_verify]", error);
    return res.status(500).json({ status: "error" });
  }
};

// ─── Logout ──────────────────────────────────────────────────────────────────

exports.logout = async (req, res) => {
  try {
    if (req.user?.id) {
      await connection_pool.query(
        `UPDATE \`${DB_PREFIX}users\`
                 SET token_version = token_version + 1
                 WHERE id = ?`,
        [req.user.id]
      );
      invalidateUserCache(req.user.id);
    }

    res.clearCookie("login");
    res.clearCookie("tfa_challenge");
    return res.redirect("/login");
  } catch (error) {
    logging.error("[logout]", error);
    res.clearCookie("login");
    res.clearCookie("tfa_challenge");
    return res.redirect("/login");
  }
};

// ─── isAuthenticated ─────────────────────────────────────────────────────────

exports.isAuthenticated = async (req, res, next) => {
  if (!req.cookies.login) {
    return res.redirect("/login");
  }

  try {
    const decoded = await promisify(jwt.verify)(req.cookies.login, jwtConfig.jwt.jwt_secret);

    const cacheKey = `user_${decoded.id}`;
    let user = userCache.get(cacheKey);

    if (!user) {
      const [[dbUser]] = await connection_pool.query(
        `SELECT id, first_name, last_name, patronymic,
                        email, phone, avatar, gender,
                        id_lang, active, tfa_enabled, token_version,
                        date_last_login
                 FROM \`${DB_PREFIX}users\`
                 WHERE id = ? LIMIT 1`,
        [decoded.id]
      );

      if (!dbUser) {
        res.clearCookie("login");
        return res.redirect("/login");
      }

      dbUser.permissions = await loadUserPermissions(dbUser.id);
      userCache.set(cacheKey, dbUser);
      user = dbUser;
    }

    if (user.active !== 1) {
      invalidateUserCache(user.id);
      res.clearCookie("login");
      return res.redirect("/login");
    }

    if (decoded.tv !== user.token_version) {
      invalidateUserCache(user.id);
      res.clearCookie("login");
      return res.redirect("/login");
    }

    req.user = user;
    return next();
  } catch (error) {
    if (error.name !== "JsonWebTokenError" && error.name !== "TokenExpiredError") {
      logging.error("[isAuthenticated]", error);
    }
    res.clearCookie("login");
    return res.redirect("/login");
  }
};

// ─── checkPermission ─────────────────────────────────────────────────────────

exports.checkPermission = (slug, action = "view") => {
  return (req, res, next) => {
    if (hasPermission(req, slug, action)) {
      return next();
    }

    if (req.originalUrl.startsWith("/api/")) {
      return res.status(403).json({
        status: "error",
        message: "Access denied",
      });
    }

    if (action === "view") {
      return res.redirect("/404");
    }

    return res.status(403).render("pages/403", {
      i18n: req,
      user: req.user,
    });
  };
};

exports._tfaInternals = {
  signTfaChallenge,
  verifyTfaChallenge,
  setTfaChallengeCookie,
  issueLoginCookie,
  invalidateUserCache,
  writeLoginLog,
};
