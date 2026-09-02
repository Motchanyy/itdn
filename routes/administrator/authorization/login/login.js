"use strict";

const express = require("express");
const router = express.Router();
const validator = require("validator");
const rateLimit = require("express-rate-limit");
const bcryptjs = require("bcryptjs");

// ─── Контролери ──────────────────────────────────────────────────────────────
const authorizationControllers = require("../../../../controllers/authorization/authorization");

// ─── Валідатор ───────────────────────────────────────────────────────────────
const validateRegister = require("../../../../validator/authorization/register");

// ─── БД ──────────────────────────────────────────────────────────────────────
const connection_pool = require("../../../../config/database/connection_pool");

// ─── Логування ───────────────────────────────────────────────────────────────
const logging = require("../../../../logging/logging");

// ─── Конфігурація ────────────────────────────────────────────────────────────
const config = require("../../../../config/config");
const configDatabase = config.get("configDatabase");
const DB_PREFIX = configDatabase.prefix;

// ─── Rate limiters ───────────────────────────────────────────────────────────
// Лічильники в БД прив'язані до юзера. Це не рятує від атаки
// "один код проти тисячі акаунтів" — тому додатково ріжемо по IP.

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) =>
    res.status(429).json({
      status: "rate_limited",
      errors: [{ field: "rate", minutes: 15 }],
    }),
});

const tfaLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) =>
    res.status(429).json({
      status: "rate_limited",
      errors: [{ field: "rate", minutes: 15 }],
    }),
});

// ─── Helpers ─────────────────────────────────────────────────────────────────
const jwt = require("jsonwebtoken");
const jwtConfig = config.get("configJWT");

function redirectIfAuthenticated(req, res, next) {
  const token = req.cookies?.login;
  if (!token) return next();

  try {
    jwt.verify(token, jwtConfig.jwt.jwt_secret);
    return res.redirect("/");
  } catch {
    res.clearCookie("login");
    return next();
  }
}

// ─── GET /login ───────────────────────────────────────────────────────────────
router.get("/login/", redirectIfAuthenticated, (req, res) => {
  res.render("pages/administrator/authorization/login/login", {
    i18n: req,
  });
});

// ─── POST /login ──────────────────────────────────────────────────────────────
router.post("/login/", loginLimiter, redirectIfAuthenticated, authorizationControllers.login);

// ─── POST /login/tfa ──────────────────────────────────────────────────────────
router.post("/login/tfa/", tfaLimiter, redirectIfAuthenticated, authorizationControllers.tfa_verify);

// ─── GET /logout ──────────────────────────────────────────────────────────────
router.get("/logout/", authorizationControllers.isAuthenticated, authorizationControllers.logout);

// ─── POST /logout ─────────────────────────────────────────────────────────────
router.post("/logout/", authorizationControllers.isAuthenticated, authorizationControllers.logout);

// ─── GET /reset-password ──────────────────────────────────────────────────────
router.get("/reset-password/", redirectIfAuthenticated, (req, res) => {
  res.render("pages/administrator/authorization/login/reset-password", {
    i18n: req,
  });
});

// ─── GET /reset-password/:token ───────────────────────────────────────────────
router.get("/reset-password/:token", redirectIfAuthenticated, async (req, res) => {
  try {
    const token = (req.params.token || "").trim();

    if (!token || token.length < 32) {
      return res.render("pages/administrator/authorization/login/new-password", {
        i18n: req,
        message: "0",
      });
    }

    const [[user]] = await connection_pool.query(
      `SELECT id
                 FROM \`${DB_PREFIX}users\`
                 WHERE reset_token         = ?
                   AND reset_token_expires > NOW()
                 LIMIT 1`,
      [token]
    );

    return res.render("pages/administrator/authorization/login/new-password", {
      i18n: req,
      message: user ? "1" : "0",
    });
  } catch (error) {
    logging.error("[reset-password/:token]", error);
    return res.status(500).render("pages/500", { i18n: req });
  }
});

// ─── GET /register/:token ─────────────────────────────────────────────────────
router.get("/register/:token", async (req, res) => {
  try {
    const token = (req.params.token || "").trim();

    if (!token || token.length !== 96) {
      return res.render("pages/administrator/authorization/login/register", {
        i18n: req,
        message: "invalid",
        email: null,
        token: null,
      });
    }

    const [[invite]] = await connection_pool.query(
      `SELECT id, email, status, expires_at
                 FROM \`${DB_PREFIX}users_invites\`
                 WHERE token = ? LIMIT 1`,
      [token]
    );

    if (!invite) {
      return res.render("pages/administrator/authorization/login/register", {
        i18n: req,
        message: "invalid",
        email: null,
        token: null,
      });
    }

    if (invite.status === 1) {
      return res.render("pages/administrator/authorization/login/register", {
        i18n: req,
        message: "already_registered",
        email: null,
        token: null,
      });
    }

    if (new Date(invite.expires_at) < new Date()) {
      return res.render("pages/administrator/authorization/login/register", {
        i18n: req,
        message: "expired",
        email: null,
        token: null,
      });
    }

    return res.render("pages/administrator/authorization/login/register", {
      i18n: req,
      message: "valid",
      email: invite.email,
      token: token,
    });
  } catch (error) {
    logging.error("[register/:token]", error);
    return res.status(500).render("pages/500", { i18n: req });
  }
});

// ─── POST /api/register ───────────────────────────────────────────────────────
router.post("/api/register", async (req, res) => {
  try {
    const data = {
      token: (req.body.token || "").trim(),
      first_name: (req.body.first_name || "").trim().replace(/\s{2,}/g, " "),
      last_name: (req.body.last_name || "").trim().replace(/\s{2,}/g, " "),
      patronymic: (req.body.patronymic || "").trim().replace(/\s{2,}/g, " "),
      password: (req.body.password || "").trim(),
      password_confirm: (req.body.password_confirm || "").trim(),
    };

    // ── Валідація через AJV ──────────────────────────────────────────
    const { valid, errors } = validateRegister(data);

    if (!valid) {
      return res.status(422).json({
        status: "error",
        errors: Object.entries(errors).map(([field, msg]) => ({ field, msg })),
      });
    }

    // ── Повторна перевірка токена ─────────────────────────────────────
    const [[invite]] = await connection_pool.query(
      `SELECT id, email, id_group, status, expires_at
                 FROM \`${DB_PREFIX}users_invites\`
                 WHERE token = ? LIMIT 1`,
      [data.token]
    );

    if (!invite || invite.status !== 0 || new Date(invite.expires_at) < new Date()) {
      return res.status(400).json({
        status: "error",
        errors: [{ field: "token", msg: "token_invalid" }],
      });
    }

    // ── Хешуємо пароль ────────────────────────────────────────────────
    const passwordHash = await bcryptjs.hash(data.password, 12);

    // ── Оновлюємо юзера який був створений зі статусом 3 ─────────────
    await connection_pool.query(
      `UPDATE \`${DB_PREFIX}users\`
                 SET first_name = ?,
                     last_name  = ?,
                     patronymic = ?,
                     password   = ?,
                     active     = 1
                 WHERE email = ?`,
      [data.first_name, data.last_name, data.patronymic, passwordHash, invite.email]
    );

    // ── Призначаємо групу якщо була вказана ───────────────────────────
    if (invite.id_group) {
      // Отримуємо id юзера
      const [[user]] = await connection_pool.query(`SELECT id FROM \`${DB_PREFIX}users\` WHERE email = ? LIMIT 1`, [invite.email]);

      if (user) {
        await connection_pool.query(
          `INSERT IGNORE INTO \`${DB_PREFIX}users_to_groups\` (id_user, id_group)
                         VALUES (?, ?)`,
          [user.id, invite.id_group]
        );
      }
    }

    // ── Позначаємо інвайт як використаний ────────────────────────────
    await connection_pool.query(
      `UPDATE \`${DB_PREFIX}users_invites\`
                SET status = 1,
                    date_accepted = NOW()
                WHERE id = ?`,
      [invite.id]
    );

    return res.json({ status: "success" });
  } catch (error) {
    logging.error("[api/register]", error);
    return res.status(500).json({ status: "error" });
  }
});

// ─── 2FA: налаштування (потребує авторизації) ─────────────────────────────────

const tfaSettingsControllers = require("../../../../controllers/authorization/tfa_settings");

const tfaSettingsLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) =>
    res.status(429).json({
      status: "rate_limited",
      errors: [{ field: "rate", minutes: 15 }],
    }),
});

router.get("/api/tfa/status", authorizationControllers.isAuthenticated, tfaSettingsControllers.status);

router.post("/api/tfa/init", tfaSettingsLimiter, authorizationControllers.isAuthenticated, tfaSettingsControllers.init);

router.post("/api/tfa/confirm", tfaSettingsLimiter, authorizationControllers.isAuthenticated, tfaSettingsControllers.confirm);

router.post("/api/tfa/disable", tfaSettingsLimiter, authorizationControllers.isAuthenticated, tfaSettingsControllers.disable);

router.post("/api/tfa/backup-codes/regenerate", tfaSettingsLimiter, authorizationControllers.isAuthenticated, tfaSettingsControllers.regenerateBackupCodes);

// ─── POST /api/administrator/reset-password ───────────────────────────────────
// router.post("/api/administrator/reset-password/", authorizationControllers.reset_password);

module.exports = router;
