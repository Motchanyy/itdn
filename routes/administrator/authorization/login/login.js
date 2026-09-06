/**
 * ===================================================================
 * ФАЙЛ: routes/administrator/authorization/login/login.js
 * ОПИС: Маршрути авторизації (Login, Logout) + API для 2FA
 * ЗАЛЕЖНОСТІ: controllers/authorization/authorization.js
 *             controllers/authorization/tfa_settings.js
 * ===================================================================
 */

const express = require("express");
const router = express.Router();
const rateLimit = require("express-rate-limit");

// Імпортуємо основний контролер авторизації (Login, Logout)
const authorizationControllers = require("../../../../controllers/authorization/authorization");

// Імпортуємо контролер налаштувань 2FA (Status, Init, Confirm, Disable, Backup)
const tfaSettingsControllers = require("../../../../controllers/authorization/tfa_settings");

// ---------------------------------------------------------------------
// ЗАХИСТ ВІД BRUTE-FORCE (RATE LIMITING)
// ---------------------------------------------------------------------

// Ліміт за IP — стеля незалежно від того, скільки email перебирає атакувальник.
const loginLimiterByIp = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 20,
	message: { status: "error", message: "Too many login attempts, please try again later." },
	standardHeaders: true,
	legacyHeaders: false,
	keyGenerator: (req) => req.ip,
});

// Ліміт за акаунтом — окремо захищає конкретний email від націленого підбору.
const loginLimiterByAccount = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 5,
	message: { status: "error", message: "Too many login attempts, please try again later." },
	standardHeaders: true,
	legacyHeaders: false,
	keyGenerator: (req) => (req.body.email ? String(req.body.email).toLowerCase().trim() : req.ip),
	skip: (req) => !req.body.email,
});

/**
 * Лімітер для операцій 2FA
 * 10 спроб на 15 хвилин (трохи м'якше, бо користувач може помилитися з кодом)
 */
const tfaSettingsLimiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 10,
	message: { status: "error", message: "Too many 2FA attempts." },
	standardHeaders: true,
	legacyHeaders: false,
});

// ---------------------------------------------------------------------
// СТОРІНКА ВХОДУ (VIEW)
// ---------------------------------------------------------------------

/**
 * GET /administrator/login
 * Відображення форми входу
 */
router.get("/", (req, res) => {
	// Якщо користувач вже авторизований, редиректимо на дашборд
	if (req.cookies && req.cookies.access_token) {
		return res.redirect("/administrator/dashboard");
	}

	res.render("pages/administrator/authorization/login/login", {
		error: null,
		message: null,
		status: null,
		email: "",
	});
});

// ---------------------------------------------------------------------
// ОСНОВНИЙ ВХІД (LOGIN)
// ---------------------------------------------------------------------

/**
 * POST /administrator/login
 * Обробка форми входу (з захищеним контролером)
 */
router.post("/", loginLimiterByIp, loginLimiterByAccount, authorizationControllers.login);

// Другий крок входу — перевірка коду 2FA (userId береться з сесії).
router.post("/tfa/", loginLimiterByIp, authorizationControllers.loginTfa);

// ---------------------------------------------------------------------
// ВИХІД (LOGOUT)
// ---------------------------------------------------------------------

/**
 * POST /administrator/logout
 * Вихід з системи
 */
router.post("/logout", (req, res) => {
	// Викликаємо метод logout з основного контролера, якщо він є,
	// або виконуємо стандартне очищення кукіс
	if (typeof authorizationControllers.logout === "function") {
		return authorizationControllers.logout(req, res);
	}

	res.clearCookie("access_token");
	res.clearCookie("refresh_token");
	res.redirect("/administrator/login");
});

// ---------------------------------------------------------------------
// 2FA API МАРШРУТИ (ПІДКЛЮЧЕНО tfaSettingsControllers)
// ---------------------------------------------------------------------

/**
 * GET /administrator/api/tfa/status
 * Перевірка статусу 2FA для поточного користувача
 */
router.get("/api/tfa/status", authorizationControllers.isAuthenticated, tfaSettingsLimiter, tfaSettingsControllers.status);

/**
 * POST /administrator/api/tfa/init
 * Ініціалізація 2FA (генерація секрету та QR-коду)
 */
router.post("/api/tfa/init", tfaSettingsLimiter, authorizationControllers.isAuthenticated, tfaSettingsControllers.init);

/**
 * POST /administrator/api/tfa/confirm
 * Підтвердження вмикання 2FA (перевірка коду)
 */
router.post("/api/tfa/confirm", tfaSettingsLimiter, authorizationControllers.isAuthenticated, tfaSettingsControllers.confirm);

/**
 * POST /administrator/api/tfa/disable
 * Вимкнення 2FA
 */
router.post("/api/tfa/disable", tfaSettingsLimiter, authorizationControllers.isAuthenticated, tfaSettingsControllers.disable);

/**
 * POST /administrator/api/tfa/backup-codes/regenerate
 * Генерація нових резервних кодів
 */
router.post("/api/tfa/backup-codes/regenerate", tfaSettingsLimiter, authorizationControllers.isAuthenticated, tfaSettingsControllers.regenerateBackupCodes);

// ---------------------------------------------------------------------
// ЕКСПОРТ
// ---------------------------------------------------------------------
module.exports = router;
