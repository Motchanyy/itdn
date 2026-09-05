"use strict";

const bcryptjs = require("bcryptjs");

const config = require("../../config/config");
const configDatabase = config.get("configDatabase");
const DB_PREFIX = configDatabase.prefix;

const logging = require("../../logging/logging");
const connection_pool = require("../../config/database/connection_pool");

const tfa = require("../../helpers/tfa");
const { encryptSecret } = require("../../helpers/crypto_tfa");
const authorization = require("./authorization");

const { invalidateUserCache, issueLoginCookie } = authorization._tfaInternals;

// ─── Крок 1: ініціалізація ───────────────────────────────────────────────────
// Генеруємо секрет у PENDING. У бойовий tfa_secret він потрапить
// лише після підтвердження кодом — інакше юзер, що закрив вкладку,
// заблокує сам себе.

exports.init = async (req, res) => {
  try {
    const password = (req.body.password || "").trim();

    if (!password) {
      return res.status(422).json({
        status: "error",
        errors: [{ field: "password" }],
      });
    }

    const [[user]] = await connection_pool.query(
      `SELECT id, email, password, tfa_enabled
             FROM \`${DB_PREFIX}users\` WHERE id = ? LIMIT 1`,
      [req.user.id]
    );

    if (!user) {
      return res.status(401).json({ status: "error" });
    }

    if (user.tfa_enabled === 1) {
      return res.status(409).json({
        status: "already_enabled",
      });
    }

    const passwordMatch = await bcryptjs.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({
        status: "invalid_password",
        errors: [{ field: "password" }],
      });
    }

    const secret = tfa.generateSecret();

    await connection_pool.query(
      `UPDATE \`${DB_PREFIX}users\`
             SET tfa_secret_pending = ?
             WHERE id = ?`,
      [encryptSecret(secret), user.id]
    );

    const otpauth = tfa.buildOtpauthUrl(user.email, secret);
    const qr = await tfa.buildQrDataUrl(otpauth);

    return res.json({
      status: "success",
      qr,
      secret, // для ручного вводу, якщо камера недоступна
    });
  } catch (error) {
    logging.error("[tfa.init]", error);
    return res.status(500).json({ status: "error" });
  }
};

// ─── Крок 2: підтвердження ───────────────────────────────────────────────────

exports.confirm = async (req, res) => {
  let conn;
  try {
    const code = tfa.normalizeCode(req.body.code);

    if (!tfa.isValidCodeFormat(code)) {
      return res.status(422).json({
        status: "error",
        errors: [{ field: "code" }],
      });
    }

    const [[user]] = await connection_pool.query(
      `SELECT id, tfa_enabled, tfa_secret_pending, token_version
             FROM \`${DB_PREFIX}users\` WHERE id = ? LIMIT 1`,
      [req.user.id]
    );

    if (!user || user.tfa_enabled === 1 || !user.tfa_secret_pending) {
      return res.status(400).json({ status: "no_pending" });
    }

    const result = tfa.verifyTotp(user.tfa_secret_pending, code, 0);

    if (!result.ok) {
      return res.status(401).json({
        status: "invalid",
        errors: [{ field: "code" }],
      });
    }

    const codes = tfa.generateBackupCodes(10);

    conn = await connection_pool.getConnection();
    await conn.beginTransaction();

    // Переносимо pending → бойовий, піднімаємо token_version
    // (розлогінює всі інші сесії — якщо акаунт вже був скомпрометований,
    // зловмисник втрачає доступ саме в цей момент)
    await conn.query(
      `UPDATE \`${DB_PREFIX}users\`
             SET tfa_secret        = tfa_secret_pending,
                 tfa_secret_pending = '',
                 tfa_enabled       = 1,
                 tfa_last_step     = ?,
                 tfa_failed_attempts = 0,
                 tfa_locked_until  = NULL,
                 token_version     = token_version + 1
             WHERE id = ? AND tfa_enabled = 0`,
      [result.step, user.id]
    );

    await conn.query(`DELETE FROM \`${DB_PREFIX}users_tfa_backup_codes\` WHERE id_user = ?`, [user.id]);

    await conn.query(
      `INSERT INTO \`${DB_PREFIX}users_tfa_backup_codes\` (id_user, code_hash)
             VALUES ?`,
      [codes.map((c) => [user.id, tfa.hashBackupCode(c)])]
    );

    await conn.commit();
    conn.release();
    conn = null;

    invalidateUserCache(user.id);

    // Перевидаємо cookie поточної сесії з новим token_version,
    // щоб юзера не викинуло одразу після увімкнення
    issueLoginCookie(res, { id: user.id, token_version: user.token_version + 1 }, false);

    return res.json({
      status: "success",
      backup_codes: codes, // показуються РІВНО ОДИН РАЗ
    });
  } catch (error) {
    if (conn) {
      try {
        await conn.rollback();
      } catch {}
      conn.release();
    }
    logging.error("[tfa.confirm]", error);
    return res.status(500).json({ status: "error" });
  }
};

// ─── Вимкнення ───────────────────────────────────────────────────────────────
// Вимагаємо і пароль, і код: інакше вкрадена сесія = миттєве зняття 2FA.

exports.disable = async (req, res) => {
  let conn;
  try {
    const password = (req.body.password || "").trim();
    const code = tfa.normalizeCode(req.body.code);

    if (!password || !tfa.isValidCodeFormat(code)) {
      return res.status(422).json({
        status: "error",
        errors: [{ field: !password ? "password" : "code" }],
      });
    }

    const [[user]] = await connection_pool.query(
      `SELECT id, password, tfa_enabled, tfa_secret, tfa_last_step, token_version
             FROM \`${DB_PREFIX}users\` WHERE id = ? LIMIT 1`,
      [req.user.id]
    );

    if (!user || user.tfa_enabled !== 1) {
      return res.status(400).json({ status: "not_enabled" });
    }

    const passwordMatch = await bcryptjs.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({
        status: "invalid_password",
        errors: [{ field: "password" }],
      });
    }

    const result = tfa.verifyTotp(user.tfa_secret, code, user.tfa_last_step);

    if (!result.ok) {
      return res.status(401).json({
        status: "invalid",
        errors: [{ field: "code" }],
      });
    }

    conn = await connection_pool.getConnection();
    await conn.beginTransaction();

    await conn.query(
      `UPDATE \`${DB_PREFIX}users\`
             SET tfa_enabled        = 0,
                 tfa_secret         = '',
                 tfa_secret_pending = '',
                 tfa_last_step      = 0,
                 tfa_failed_attempts = 0,
                 tfa_locked_until   = NULL,
                 token_version      = token_version + 1
             WHERE id = ?`,
      [user.id]
    );

    await conn.query(`DELETE FROM \`${DB_PREFIX}users_tfa_backup_codes\` WHERE id_user = ?`, [user.id]);

    await conn.commit();
    conn.release();
    conn = null;

    invalidateUserCache(user.id);
    issueLoginCookie(res, { id: user.id, token_version: user.token_version + 1 }, false);

    return res.json({ status: "success" });
  } catch (error) {
    if (conn) {
      try {
        await conn.rollback();
      } catch {}
      conn.release();
    }
    logging.error("[tfa.disable]", error);
    return res.status(500).json({ status: "error" });
  }
};

// ─── Регенерація backup-кодів ────────────────────────────────────────────────

exports.regenerateBackupCodes = async (req, res) => {
  let conn;
  try {
    const password = (req.body.password || "").trim();
    const code = tfa.normalizeCode(req.body.code);

    if (!password || !tfa.isValidCodeFormat(code)) {
      return res.status(422).json({
        status: "error",
        errors: [{ field: !password ? "password" : "code" }],
      });
    }

    const [[user]] = await connection_pool.query(
      `SELECT id, password, tfa_enabled, tfa_secret, tfa_last_step
             FROM \`${DB_PREFIX}users\` WHERE id = ? LIMIT 1`,
      [req.user.id]
    );

    if (!user || user.tfa_enabled !== 1) {
      return res.status(400).json({ status: "not_enabled" });
    }

    const passwordMatch = await bcryptjs.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({
        status: "invalid_password",
        errors: [{ field: "password" }],
      });
    }

    const result = tfa.verifyTotp(user.tfa_secret, code, user.tfa_last_step);
    if (!result.ok) {
      return res.status(401).json({
        status: "invalid",
        errors: [{ field: "code" }],
      });
    }

    const codes = tfa.generateBackupCodes(10);

    conn = await connection_pool.getConnection();
    await conn.beginTransaction();

    await conn.query(`DELETE FROM \`${DB_PREFIX}users_tfa_backup_codes\` WHERE id_user = ?`, [user.id]);

    await conn.query(
      `INSERT INTO \`${DB_PREFIX}users_tfa_backup_codes\` (id_user, code_hash)
             VALUES ?`,
      [codes.map((c) => [user.id, tfa.hashBackupCode(c)])]
    );

    await conn.query(
      `UPDATE \`${DB_PREFIX}users\`
             SET tfa_last_step = GREATEST(tfa_last_step, ?)
             WHERE id = ?`,
      [result.step, user.id]
    );

    await conn.commit();
    conn.release();
    conn = null;

    return res.json({ status: "success", backup_codes: codes });
  } catch (error) {
    if (conn) {
      try {
        await conn.rollback();
      } catch {}
      conn.release();
    }
    logging.error("[tfa.regenerate]", error);
    return res.status(500).json({ status: "error" });
  }
};

// ─── Статус (для сторінки налаштувань) ───────────────────────────────────────

exports.status = async (req, res) => {
  try {
    const [[row]] = await connection_pool.query(
      `SELECT u.tfa_enabled,
                    (SELECT COUNT(*) FROM \`${DB_PREFIX}users_tfa_backup_codes\`
                     WHERE id_user = u.id AND used_at IS NULL) AS codes_left
             FROM \`${DB_PREFIX}users\` u
             WHERE u.id = ? LIMIT 1`,
      [req.user.id]
    );

    return res.json({
      status: "success",
      tfa_enabled: row?.tfa_enabled === 1,
      codes_left: Number(row?.codes_left || 0),
    });
  } catch (error) {
    logging.error("[tfa.status]", error);
    return res.status(500).json({ status: "error" });
  }
};
