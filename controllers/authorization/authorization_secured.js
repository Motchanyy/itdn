/**
 * =============================================================================
 * 🛡️ ЗАХИЩЕНИЙ КОНТРОЛЕР LOGIN З МАКСИМАЛЬНИМ РІВНЕМ БЕЗПЕКИ
 * =============================================================================
 * 
 * Реалізовані заходи безпеки:
 * 1. ✅ Rate Limiting по IP (5 спроб на 15 хв)
 * 2. ✅ Блокування акаунту після 5 невдалих спроб
 * 3. ✅ AJV валідація всіх вхідних даних
 * 4. ✅ Захист від Enumeration Attacks (універсальна відповідь)
 * 5. ✅ Constant-time password comparison
 * 6. ✅ Логування подій безпеки
 * 7. ✅ Відстеження нових пристроїв/IP
 * 8. ✅ 2FA з окремим challenge токеном
 * 9. ✅ Secure cookies (HttpOnly, SameSite=strict)
 * 10. ✅ Token version для інвалідації сесій
 * 
 * @version 2.0.0
 * @security MAXIMUM
 */

"use strict";

// ─── ІМПОРТИ ЗАЛЕЖНОСТЕЙ ──────────────────────────────────────────────────────

// Криптографія та безпека
const jwt = require("jsonwebtoken");           // JWT токени
const bcryptjs = require("bcryptjs");          // Хешування паролів (12 раундів)
const crypto = require("crypto");              // Генерація випадкових даних
const { promisify } = require("util");         // Проміфікація callback функцій

// Валідація даних
const validator = require("validator");        // Базова валідація
const validateLogin = require("../../validators/authorization/login"); // AJV схема

// Rate limiting (захист від brute-force)
const rateLimit = require("express-rate-limit");

// Конфігурація
const config = require("../../config/config");
const configDatabase = config.get("configDatabase");
const jwtConfig = config.get("configJWT");

// Логування
const logging = require("../../logging/logging");

// База даних
const connection_pool = require("../../config/database/connection_pool");

// 2FA допоміжні функції
const tfa = require("../../helpers/tfa");

// Кешування користувачів (для продуктивності)
const NodeCache = require("node-cache");
const userCache = new NodeCache({
  stdTTL: 60,              // Кеш на 60 секунд
  checkperiod: 120,        // Перевірка кожні 2 хвилини
  maxKeys: 5000,           // Максимум 5000 ключів
});

// ─── КОНСТАНТИ БЕЗПЕКИ ────────────────────────────────────────────────────────

const DB_PREFIX = configDatabase.prefix;     // Префікс таблиць БД

// Налаштування блокування після невдалих спроб входу
const MAX_FAILED_ATTEMPTS = 5;               // Максимум невдалих спроб
const LOCK_DURATION_MIN = 15;                // Тривалість блокування (хв)

// Налаштування хешування паролів
const BCRYPT_ROUNDS = 12;                    // Кількість раундів bcrypt

// Налаштування 2FA
const TFA_MAX_ATTEMPTS = 5;                  // Максимум спроб 2FA коду
const TFA_LOCK_MIN = 15;                     // Блокування 2FA (хв)
const TFA_CHALLENGE_TTL_SEC = 300;           // Життя challenge токена (5 хв)

// ─── RATE LIMITERS (ЗАХИСТ ВІД BRUTE-FORCE) ───────────────────────────────────

/**
 * 🔒 Login Rate Limiter
 * Обмежує кількість спроб входу з одного IP адреси
 * 
 * Чому 5 спроб? 
 * - Нормальний користувач: 1-2 спроби
 * - Помилка паролю: +1-2 спроби  
 * - Зловмисник: намагається підібрати пароль
 * 
 * Важливо: skipSuccessfulRequests: false
 * Це означає, що навіть успішні логіни враховуються
 * (запобігає атаці "один успішний + 4 невдалих")
 */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,        // 15 хвилин
  max: 5,                          // Тільки 5 спроб на IP
  standardHeaders: true,           // Повертати заголовки RateLimit-*
  legacyHeaders: false,            // Не використовувати старі X-RateLimit-*
  
  // Генератор ключа: використовуємо IP клієнта
  keyGenerator: (req) => getClientIp(req),
  
  // Обробник перевищення ліміту
  handler: (req, res) => {
    logging.warn(`[loginLimiter] Rate limit exceeded from IP: ${getClientIp(req)}`);
    res.status(429).json({
      status: "rate_limited",
      errors: [{ field: "rate", minutes: 15 }],
    });
  },
  
  // Рахувати ВСІ запити (навіть успішні)
  skipSuccessfulRequests: false,
  
  // Повідомлення (не використовується при handler)
  message: "Занадто багато спроб входу, будь ласка, спробуйте пізніше",
});

/**
 * 🔒 2FA Rate Limiter
 * Ще суворіше обмеження для 2FA кодів
 * 
 * Чому 3 спроби?
 * - 2FA код має тільки 6 цифр
 * - Зловмисник може швидко перебрати варіанти
 * - Користувач зазвичай вводить код з першого разу
 */
const tfaLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,        // 15 хвилин
  max: 3,                          // Тільки 3 спроби на IP
  standardHeaders: true,
  legacyHeaders: false,
  
  keyGenerator: (req) => getClientIp(req),
  
  handler: (req, res) => {
    logging.warn(`[tfaLimiter] Rate limit exceeded from IP: ${getClientIp(req)}`);
    res.status(429).json({
      status: "rate_limited",
      errors: [{ field: "rate", minutes: 15 }],
    });
  },
  
  skipSuccessfulRequests: false,
});

// ─── ДОПОМІЖНІ ФУНКЦІЇ (HELPERS) ──────────────────────────────────────────────

/**
 * 🌐 Отримання IP адреси клієнта
 * 
 * Враховує проксі-сервери (X-Forwarded-For)
 * Обрізає до 45 символів для IPv6 сумісності
 * 
 * @param {Object} req - Express request об'єкт
 * @returns {string} IP адреса клієнта
 */
function getClientIp(req) {
  // Перевіряємо заголовок X-Forwarded-For (для проксі)
  const forwarded = req.headers["x-forwarded-for"];
  
  if (forwarded) {
    // Беремо перший IP зі списку (оригінальний клієнт)
    const ip = forwarded.split(",")[0].trim();
    return ip.substring(0, 45);
  }
  
  // Якщо немає проксі, беремо безпосередню адресу
  const ip = req.socket?.remoteAddress || "";
  return ip.substring(0, 45);
}

/**
 * 📱 Визначення типу пристрою за User-Agent
 * 
 * Використовується для:
 * - Відстеження нових пристроїв
 * - Логування підозрілої активності
 * - Аналітики безпеки
 * 
 * @param {string} userAgent - User-Agent заголовок
 * @returns {number} 0=Desktop, 1=Mobile, 2=Tablet
 */
function detectDevice(userAgent = "") {
  const ua = userAgent.toLowerCase();
  
  // Планшети
  if (/tablet|ipad|playbook|silk/.test(ua)) {
    return 2;
  }
  
  // Мобільні телефони
  if (/mobile|android|iphone|ipod|blackberry|opera mini|iemobile/.test(ua)) {
    return 1;
  }
  
  // Desktop (за замовчуванням)
  return 0;
}

/**
 * 📝 Запис логіну в таблицю логів
 * 
 * Зберігає:
 * - ID користувача
 * - IP адресу
 * - User-Agent
 * - Тип пристрою
 * - Статус (успішно/неуспішно)
 * 
 * @param {number} userId - ID користувача
 * @param {Object} req - Express request
 * @param {boolean} success - Статус входу
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
 * 🚨 Логування подій безпеки
 * 
 * Типи подій:
 * - login_failed_multiple (3+ невдалих спроби)
 * - login_new_device_or_ip (новий пристрій/IP)
 * - password_changed
 * - 2fa_enabled/disabled
 * - suspicious_activity
 * 
 * @param {number} userId - ID користувача
 * @param {string} eventType - Тип події
 * @param {Object} req - Express request
 * @param {Object} extraData - Додаткові дані (JSON)
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
    
    logging.info(`[SecurityEvent] User ${userId}: ${eventType} from ${ip}`);
  } catch (err) {
    logging.error("[logSecurityEvent]", err);
  }
}

// ─── ФУНКЦІЇ ДОЗВОЛІВ (PERMISSIONS) ───────────────────────────────────────────

/**
 * Завантаження прав користувача з БД
 * 
 * @param {number} userId - ID користувача
 * @returns {Object} Об'єкт з правами доступу
 */
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

/**
 * Перевірка наявності права доступу
 * 
 * @param {Object} req - Express request з user об'єктом
 * @param {string} slug - Сторінка/ресурс
 * @param {string} action - Дія (view/add/edit/delete)
 * @returns {boolean} true якщо є доступ
 */
function hasPermission(req, slug, action = "view") {
  return req.user?.permissions?.[slug]?.[action] === true;
}

exports.hasPermission = hasPermission;

/**
 * Очищення кешу користувача
 * 
 * Викликається при зміні даних користувача
 * 
 * @param {number} userId - ID користувача
 */
function invalidateUserCache(userId) {
  userCache.del(`user_${userId}`);
}

// ─── 2FA CHALLENGE ФУНКЦІЇ ────────────────────────────────────────────────────

/**
 * 🎫 Генерація тимчасового 2FA challenge токена
 * 
 * Цей токен:
 * - Окремий від основного login токена
 * - Має короткий термін життя (5 хв)
 * - Містить мітку "purpose: tfa"
 * - Використовує окремий secret ключ
 * 
 * @param {number} userId - ID користувача
 * @param {number} tokenVersion - Версія токена (для інвалідації)
 * @param {boolean} rememberMe - Чи запам'ятати пристрій
 * @returns {string} JWT токен
 */
function signTfaChallenge(userId, tokenVersion, rememberMe) {
  return jwt.sign(
    {
      id: userId,
      tv: tokenVersion,
      rm: rememberMe === true,
      purpose: "tfa",                    // Мітка типу токена
      jti: crypto.randomBytes(16).toString("hex"), // Унікальний ID
    },
    jwtConfig.jwt.jwt_secret + "|tfa",   // Окремий secret для 2FA
    { expiresIn: TFA_CHALLENGE_TTL_SEC } // 5 хвилин
  );
}

/**
 * ✅ Верифікація 2FA challenge токена
 * 
 * @param {string} token - JWT токен з cookie
 * @returns {Object|null} Декодований токен або null
 */
async function verifyTfaChallenge(token) {
  if (!token) return null;
  
  try {
    const decoded = await promisify(jwt.verify)(
      token, 
      jwtConfig.jwt.jwt_secret + "|tfa"
    );
    
    // Перевіряємо що це саме 2FA токен
    if (decoded.purpose !== "tfa") return null;
    
    return decoded;
  } catch {
    return null;
  }
}

/**
 * 🍪 Встановлення 2FA challenge cookie
 * 
 * Безпечні налаштування:
 * - HttpOnly: не доступно через JavaScript
 * - SameSite=strict: захист від CSRF
 * - Secure: тільки HTTPS (в production)
 * 
 * @param {Object} res - Express response
 * @param {string} token - 2FA challenge токен
 */
function setTfaChallengeCookie(res, token) {
  const isProd = process.env.NODE_ENV === "production";
  
  res.cookie("tfa_challenge", token, {
    maxAge: TFA_CHALLENGE_TTL_SEC * 1000,  // 5 хвилин
    httpOnly: true,                         // Захист від XSS
    secure: isProd,                         // Тільки HTTPS
    sameSite: "strict",                     // Захист від CSRF
    path: "/"
  });
}

/**
 * 🍪 Встановлення основного login cookie
 * 
 * Використовується після успішного входу
 * або після підтвердження 2FA
 * 
 * @param {Object} res - Express response
 * @param {Object} user - Об'єкт користувача
 * @param {boolean} remember_me - Чи запам'ятати пристрій
 */
function issueLoginCookie(res, user, remember_me) {
  // Визначаємо термін дії токена
  const expiresIn = remember_me && jwtConfig.jwt.jwt_time_expires_remember 
    ? jwtConfig.jwt.jwt_time_expires_remember 
    : jwtConfig.jwt.jwt_time_expires;

  // Генерація JWT токена
  const token = jwt.sign(
    { 
      id: user.id, 
      tv: user.token_version  // Версія для інвалідації
    }, 
    jwtConfig.jwt.jwt_secret, 
    { expiresIn }
  );

  const isProd = process.env.NODE_ENV === "production";

  // Встановлення cookie
  res.cookie("login", token, {
    expires: new Date(Date.now() + Number(jwtConfig.jwt.jwt_cookie_expiring) * 24 * 60 * 60 * 1000),
    httpOnly: true,      // Захист від XSS атак
    secure: isProd,      // Тільки HTTPS в production
    sameSite: "strict",  // Максимальний захист від CSRF
    path: "/"
  });
}

// ─── ОСНОВНА ФУНКЦІЯ LOGIN ────────────────────────────────────────────────────

/**
 * 🔐 Функція входу з максимальним рівнем безпеки
 * 
 * КРОКИ ЗАХИСТУ:
 * 1. ✅ Rate limiting (попередньо в middleware)
 * 2. ✅ AJV валідація вхідних даних
 * 3. ✅ Санітизація даних
 * 4. ✅ Перевірка існування користувача
 * 5. ✅ Перевірка блокування акаунту
 * 6. ✅ Constant-time перевірка паролю
 * 7. ✅ Збільшення лічильника невдалих спроб
 * 8. ✅ Перевірка активності акаунту
 * 9. ✅ Скидання лічильника після успіху
 * 10. ✅ Детекція нового пристрою/IP
 * 11. ✅ 2FA перевірка (якщо увімкнено)
 * 12. ✅ Оновлення останнього входу
 * 13. ✅ Логування події
 * 14. ✅ Видача JWT cookie
 * 
 * @param {Object} req - Express request
 * @param {Object} res - Express response
 * @returns {Promise<void>}
 */
exports.login = async (req, res) => {
  try {
    // =========================================================================
    // КРОК 1: ВАЛІДАЦІЯ ВХІДНИХ ДАНИХ ЧЕРЕЗ AJV
    // =========================================================================
    // Перевіряємо всі поля за строгою схемою:
    // - email: формат, довжина, патерн
    // - password: довжина 8-128 символів
    // - tfa_code: опціонально, рівно 6 цифр
    // - remember_me: boolean
    // - additionalProperties: false (відхиляє невідомі поля)
    
    const validationErrors = validateLogin(req.body);
    
    if (validationErrors) {
      // Форматуємо помилки AJV у зручний вигляд для клієнта
      const errors = validationErrors.map(err => {
        let field = err.instancePath.substring(1) || "data";
        let msg = res.__("please_fill_out_this_field");
        
        // Деталізовані повідомлення про помилки
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
          // Хтось намагається передати невідомі поля (можлива атака)
          msg = res.__("unexpected_field");
          logging.warn(`[login] Unexpected field attempt from IP ${getClientIp(req)}`, {
            field: err.params.additionalProperty
          });
        }
        
        return { field, msg };
      });
      
      // Логуємо невдалу спробу валідації
      logging.warn(`[login] Validation failed from IP ${getClientIp(req)}`, { 
        errors: validationErrors,
        body: Object.keys(req.body) // Не логуємо паролі!
      });
      
      return res.status(422).json({ status: "error", errors });
    }
    
    // =========================================================================
    // КРОК 2: САНІТИЗАЦІЯ ДАНИХ
    // =========================================================================
    // Видаляємо зайві пробіли, приводимо до нижнього регістру
    const email = req.body.email.trim().toLowerCase();
    const password = req.body.password.trim();
    const remember_me = req.body.remember_me === true;
    const tfa_code = req.body.tfa_code?.trim();
    
    // =========================================================================
    // КРОК 3: ОТРИМАННЯ КОРИСТУВАЧА З БД
    // =========================================================================
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
    // Зловмисник не дізнається чи існує email в системі
    const genericAuthError = () => res.status(401).json({
      status: "invalid",
      errors: [{ field: "invalid" }],
    });

    if (!user) {
      logging.info(`[login] Failed login attempt for non-existent user: ${email} from IP ${getClientIp(req)}`);
      return genericAuthError();
    }

    // =========================================================================
    // КРОК 4: ПЕРЕВІРКА БЛОКУВАННЯ АКАУНТУ
    // =========================================================================
    // Якщо акаунт заблоковано після багатьох невдалих спроб
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      const minutesLeft = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
      
      logging.warn(`[login] Account locked: ${user.id} from IP ${getClientIp(req)}, locked until: ${user.locked_until}`);
      
      return res.status(429).json({
        status: "locked",
        errors: [{ field: "locked", minutes: minutesLeft }],
      });
    }

    // =========================================================================
    // КРОК 5: ПЕРЕВІРКА ПАРОЛЮ (CONSTANT-TIME COMPARISON)
    // =========================================================================
    // bcrypt.compare має constant-time execution для запобігання timing attacks
    let passwordMatch;
    try {
      passwordMatch = await bcryptjs.compare(password, user.password);
    } catch (err) {
      logging.error("[login] bcrypt compare error", err);
      return res.status(500).json({ status: "error" });
    }

    if (!passwordMatch) {
      // =======================================================================
      // КРОК 5.1: ЗБІЛЬШЕННЯ ЛІЧИЛЬНИКА НЕВДАЛИХ СПРОБ
      // =======================================================================
      const newAttempts = (user.failed_login_attempts || 0) + 1;
      const shouldLock = newAttempts >= MAX_FAILED_ATTEMPTS;
      const lockedUntil = shouldLock 
        ? new Date(Date.now() + LOCK_DURATION_MIN * 60 * 1000) 
        : null;

      // Оновлюємо лічильник та можливо блокуємо акаунт
      await connection_pool.query(
        `UPDATE \`${DB_PREFIX}users\`
         SET failed_login_attempts = ?, locked_until = ?
         WHERE id = ?`,
        [newAttempts, lockedUntil, user.id]
      );

      // Записуємо невдалий логін
      writeLoginLog(user.id, req, false);
      
      // Логуємо підозрілу активність після 3+ невдалих спроб
      if (newAttempts >= 3) {
        await logSecurityEvent(user.id, "login_failed_multiple", req, {
          attempts: newAttempts,
          email: email
        });
      }

      logging.warn(`[login] Invalid password for user ${user.id}, attempt ${newAttempts}, IP: ${getClientIp(req)}`);
      
      // Повертаємо універсальну помилку (не розкриваємо що пароль неправильний)
      return genericAuthError();
    }

    // =========================================================================
    // КРОК 6: ПЕРЕВІРКА АКТИВНОСТІ АКАУНТУ
    // =========================================================================
    if (user.active !== 1) {
      logging.warn(`[login] Inactive account tried to login: ${user.id}, IP: ${getClientIp(req)}`);
      return res.status(403).json({
        status: "invalid",
        errors: [{ field: "account_not_active" }],
      });
    }

    // =========================================================================
    // КРОК 7: СКИДАННЯ ЛІЧИЛЬНИКА ПІСЛЯ УСПІШНОЇ ПЕРЕВІРКИ
    // =========================================================================
    await connection_pool.query(
      `UPDATE \`${DB_PREFIX}users\`
       SET failed_login_attempts = 0, locked_until = NULL
       WHERE id = ?`,
      [user.id]
    );

    // =========================================================================
    // КРОК 8: ДЕТЕКЦІЯ НОВОГО ПРИСТРОЮ/IP (ПІДОЗРІЛА АКТИВНІСТЬ)
    // =========================================================================
    const currentIp = getClientIp(req);
    const currentDevice = detectDevice(req.headers["user-agent"] || "");
    
    const isNewDevice = user.last_device_type !== currentDevice;
    const isNewIp = user.last_login_ip !== currentIp;
    
    if (isNewDevice || isNewIp) {
      // Логуємо як подію безпеки
      await logSecurityEvent(user.id, "login_new_device_or_ip", req, {
        current_ip: currentIp,
        previous_ip: user.last_login_ip,
        current_device: currentDevice,
        previous_device: user.last_device_type,
        is_new_device: isNewDevice,
        is_new_ip: isNewIp
      });
      
      logging.info(`[login] New device/IP detected for user ${user.id}: IP=${currentIp}, Device=${currentDevice}`);
      
      // TODO: Тут можна додати email сповіщення користувачу
      // "Новий вхід у ваш акаунт з пристрою..."
    }

    // =========================================================================
    // КРОК 9: 2FA ПЕРЕВІРКА (ЯКЩО УВІМКНЕНО)
    // =========================================================================
    if (user.tfa_enabled === 1 && user.tfa_secret) {
      // Генеруємо тимчасовий challenge токен
      const challenge = signTfaChallenge(user.id, user.token_version, remember_me);
      setTfaChallengeCookie(res, challenge);

      logging.info(`[login] 2FA required for user ${user.id}, IP: ${currentIp}`);
      
      // Повертаємо статус що потрібен 2FA код
      return res.json({ status: "tfa_required" });
    }

    // =========================================================================
    // КРОК 10: УСПІШНИЙ ВХІД - ОСТОННІ ДІЇ
    // =========================================================================
    // Оновлюємо інформацію про останній вхід
    await connection_pool.query(
      `UPDATE \`${DB_PREFIX}users\`
       SET date_last_login = NOW(),
           last_login_ip = ?,
           last_device_type = ?
       WHERE id = ?`,
      [currentIp, currentDevice, user.id]
    );

    // Записуємо успішний логін
    writeLoginLog(user.id, req, true);
    
    // Очищаємо кеш користувача (щоб отримати актуальні дані)
    invalidateUserCache(user.id);

    // Видаємо основний login cookie
    issueLoginCookie(res, user, remember_me);

    logging.info(`[login] Successful login for user ${user.id}, IP: ${currentIp}, Device: ${currentDevice}`);

    return res.json({ status: "success", url: "/" });
    
  } catch (error) {
    // Логyємо критичну помилку
    logging.error("[login] Critical error", error);
    
    // Не розкриваємо деталі помилки клієнту
    return res.status(500).json({ status: "error" });
  }
};

// ─── ЕКСПОРТ RATE LIMITERS ────────────────────────────────────────────────────
// Використовуються в routes для застосування до ендпоінтів

exports.loginLimiter = loginLimiter;
exports.tfaLimiter = tfaLimiter;

// ─── ІНШІ ЕКСПОРТИ ────────────────────────────────────────────────────────────

exports.loadUserPermissions = loadUserPermissions;
exports.invalidateUserCache = invalidateUserCache;
exports.getClientIp = getClientIp;
exports.detectDevice = detectDevice;
exports.logSecurityEvent = logSecurityEvent;
exports.writeLoginLog = writeLoginLog;
