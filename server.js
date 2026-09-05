/**
 * =====================================================
 * ГОЛОВНИЙ ФАЙЛ ДОДАТКУ (server.js)
 * =====================================================
 * Відповідає за:
 * - Ініціалізацію Express додатку
 * - Налаштування middleware
 * - Підключення маршрутів
 * - Запуск HTTP сервера
 * - Планування cron-задач
 * =====================================================
 */

// Генерація ключів
require("./ensure-env").ensureEnv();
// END Генерація ключів

// ─── ІМПОРТ ЗАЛЕЖНОСТЕЙ ────────────────────────────────
const express = require("express");
const http = require("http");
const path = require("path");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const compression = require("compression");
const cors = require("cors");
const cron = require("node-cron");

const helmet = require("helmet");
const session = require("express-session");

// Внутрішні модулі
const i18n = require("./config/i18n/i18n");
const loadLanguages = require("./middlewares/languages");

// ─── ІНІЦІАЛІЗАЦІЯ EXPRESS ДОДАТКУ ────────────────────
const app = express();

// Довіряємо ЛИШЕ довіреному проксі (Nginx/Cloudflare перед додатком).
// Число = кількість проксі-хопів. Тоді req.ip коректний, а x-forwarded-for
// від клієнта не підробляється. Підберіть під вашу інфраструктуру.
app.set("trust proxy", 1);

// Захисні HTTP-заголовки (CSP, HSTS, X-Frame-Options тощо).
app.use(helmet());

// ─── СТВОРЕННЯ HTTP СЕРВЕРА ───────────────────────────
const server = http.createServer(app);

// ─── ІНІЦІАЛІЗАЦІЯ SOCKET.IO ──────────────────────────
// Підключаємо socket.io для real-time комунікації
const { setupSocketIO, getIO } = require("./controllers/socket/socket");
const io = setupSocketIO(server);

// ─── ІНІЦІАЛІЗАЦІЯ VIBER БОТА ─────────────────────────
// Webhook для інтеграції з Viber
const viber_bot = require("./routes/contact-center/viber/viber");
app.use("/viber/webhook/", viber_bot.middleware());

// ─── INSTAGRAM WEBHOOK (сире тіло для перевірки підпису) ──
// Має бути ДО bodyParser.json(), інакше req.body не буде Buffer.
app.use("/", require("./routes/contact-center/instagram/webhook"));

// ─── ЗАВАНТАЖЕННЯ КОНФІГУРАЦІЇ ────────────────────────
const config = require("./config/config");
const configServer = config.get("configServer");

// ═══════════════════════════════════════════════════════
// НАЛАШТУВАННЯ БАЗОВИХ MIDDLEWARE
// ═══════════════════════════════════════════════════════

// ─── ПАРСИНГ ТІЛА ЗАПИТУ ──────────────────────────────
// Для обробки даних з HTML форм
app.use(bodyParser.urlencoded({ extended: false }));
// Для обробки JSON запитів
app.use(bodyParser.json());
app.use(express.json({ limit: "300kb" })); // Обмеження розміру JSON до 300kb

// ─── СТИСНЕННЯ ВІДПОВІДЕЙ ─────────────────────────────
// Зменшує розмір відповідей для швидшого завантаження
app.use(compression());

// ─── СТАТИЧНІ ФАЙЛИ ──────────────────────────────────
// Обслуговування статичних файлів (CSS, JS, зображення)
const assetsPath = path.join(__dirname, "assets");
app.use("/assets", express.static(assetsPath));

// ─── COOKIES ТА CORS ─────────────────────────────────
// Парсинг cookies з запитів
app.use(cookieParser());

// CORS лише для довірених доменів + підтримка кукі.
// Впишіть реальні домени вашої CRM у CORS_ORIGINS через кому.
const allowedOrigins = (process.env.CORS_ORIGINS || "")
	.split(",")
	.map((s) => s.trim())
	.filter(Boolean);
app.use(
	cors({
		origin: (origin, cb) => {
			if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
			return cb(new Error("Not allowed by CORS"));
		},
		credentials: true,
	})
);

// Серверні сесії — потрібні для зберігання факту проходження 1-го фактора
// (щоб не тягати пароль через форму). У проді підключіть store (Redis), не MemoryStore.
app.use(
	session({
		secret: process.env.SESSION_SECRET,
		name: "sid",
		resave: false,
		saveUninitialized: false,
		cookie: {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			sameSite: "strict",
			maxAge: 10 * 60 * 1000, // pending-2FA живе недовго
		},
	})
);

// ─── НАЛАШТУВАННЯ ШАБЛОНІЗАТОРА ──────────────────────
// Використовуємо EJS як шаблонізатор
app.set("view engine", "ejs");

// ═══════════════════════════════════════════════════════
// НАЛАШТУВАННЯ ІНТЕРНАЦІОНАЛІЗАЦІЇ ТА ЛОКАЛІЗАЦІЇ
// ═══════════════════════════════════════════════════════

// Ініціалізація i18n для багатомовності
app.use(i18n.init);

// Завантаження активних мов з бази даних
// ВАЖЛИВО: Має бути перед маршрутами, щоб res.locals.languages був доступний
app.use(loadLanguages);

// ═══════════════════════════════════════════════════════
// НАЛАШТУВАННЯ ПРАВ ДОСТУПУ
// ═══════════════════════════════════════════════════════

/**
 * Middleware для перевірки прав доступу
 * Додає функцію res.locals.can для використання в шаблонах
 * Приклад: res.locals.can('orders', 'edit')
 */
app.use((req, res, next) => {
	res.locals.can = (slug, action = "view") => req.user?.permissions?.[slug]?.[action] === true;
	next();
});

// ═══════════════════════════════════════════════════════
// ПІДКЛЮЧЕННЯ МАРШРУТІВ
// ═══════════════════════════════════════════════════════

// ─── ГОЛОВНА СТОРІНКА ────────────────────────────────
app.use("/", require("./routes/routes/routes"));
app.use("/", require("./routes/index/index"));

// ─── ЗАМОВЛЕННЯ ──────────────────────────────────────
app.use("/", require("./routes/orders/orders"));
app.use(require("./routes/orders/tokens/tokens"));
app.use(require("./routes/orders/integrations/integrations"));
app.use(require("./routes/orders/receiver")); // Прийом замовлень із зовнішніх джерел

// Контролери для відновлення черг при запуску
const { recoverOnStartup } = require("./controllers/orders/inboxProcessor");
const { recoverOutboxOnStartup } = require("./controllers/orders/outboxProcessor");
const { recoverCartInboxOnStartup } = require("./controllers/orders/cartInboxProcessor");

// ─── ПОКИНУТІ КОШИКИ (Abandoned Cart) ────────────────
app.use("/", require("./routes/customers/customers"));
app.use("/", require("./routes/orders/abandoned-cart/abandoned-cart"));
app.use("/", require("./routes/orders/abandoned-cart/services/services"));
app.use("/", require("./routes/orders/abandoned-cart/report/report"));
app.use("/", require("./routes/orders/abandoned-cart/dispatch/dispatch"));
app.use("/", require("./routes/orders/abandoned-cart/recover-link/recover-link"));

// ─── АНАЛІТИКА ───────────────────────────────────────
app.use("/", require("./routes/analytics/index/analytics"));

// ─── КАТАЛОГ ────────────────────────────────────────
app.use("/", require("./routes/catalog/brands/brands"));

// ─── АВТОРИЗАЦІЯ ТА АДМІНІСТРУВАННЯ ─────────────────
app.use("/", require("./routes/administrator/authorization/login/login"));

// ─── КОНТАКТ-ЦЕНТР ──────────────────────────────────
app.use("/", require("./routes/contact-center/contact-center"));
app.use("/", require("./routes/contact-center/telegram/telegram"));
app.use("/", require("./routes/contact-center/web-chat/web-chat"));
app.use("/", require("./routes/contact-center/instagram/instagram"));

// ─── CRM МОДУЛІ ─────────────────────────────────────
app.use("/", require("./routes/leads/leads"));
app.use("/", require("./routes/deals/deals"));
app.use("/", require("./routes/users/users"));
app.use("/", require("./routes/profile/profile"));

// ─── НАЛАШТУВАННЯ ТА ІНТЕГРАЦІЇ ─────────────────────
app.use("/", require("./routes/notifications/notifications"));
app.use("/", require("./routes/clients/clients"));
app.use("/", require("./routes/settings/integration/integration"));
app.use("/", require("./routes/settings/email/email"));

// ═══════════════════════════════════════════════════════
// ОБРОБКА ПОМИЛОК
// ═══════════════════════════════════════════════════════

/**
 * Глобальний обробник помилок
 * Повинен бути останнім middleware
 */
app.use((err, req, res, next) => {
	console.error("Помилка:", err);

	// Логування помилки в файл (опціонально)
	// logging.error(err);

	res.status(err.status || 500);
	res.render("pages/error/404", {
		message: err.message,
		error: process.env.NODE_ENV === "development" ? err : {},
	});
});

// ─── ОБРОБКА 404 (СТОРІНКУ НЕ ЗНАЙДЕНО) ─────────────
app.use((req, res) => {
	res.status(404).render("pages/error/404", {
		message: "Сторінку не знайдено",
		error: { status: 404 },
	});
});

// ═══════════════════════════════════════════════════════
// НАЛАШТУВАННЯ CRON-ЗАДАЧ ТА АВТОМАТИЗАЦІЇ
// ═══════════════════════════════════════════════════════

// Імпорт функцій для аналітики
const { rebuild, verify } = require("./cron/analytics/rebuildStats");

// Імпорт функцій для нагадувань календаря
const { tick: calendarReminderTick, cleanup: calendarReminderCleanup } = require("./cron/notifications/calendar-reminder-cron");

const { refreshTick: igRefreshTick } = require("./cron/notifications/instagram-refresh-cron");

// ═══════════════════════════════════════════════════════
// ЗАПУСК СЕРВЕРА
// ═══════════════════════════════════════════════════════

server.listen(configServer.port, () => {
	console.log("Сайт запущений.\nПорт: " + configServer.port);

	// ─── ВІДНОВЛЕННЯ ЧЕРГ ПРИ ЗАПУСКУ ─────────────────
	// Відновлення обробки повідомлень після перезапуску
	recoverOnStartup();
	recoverOutboxOnStartup();
	recoverCartInboxOnStartup();

	// ─── АВТОМАТИЗАЦІЯ АНАЛІТИКИ ─────────────────────
	let isAnalyticsRunning = false;

	/**
	 * Функція для запуску аналітики
	 * @param {number} days - Кількість днів для аналізу
	 * @param {string} label - Назва задачі для логування
	 */
	const runAnalytics = (days, label) => {
		if (isAnalyticsRunning) {
			return console.log(`[analytics] ${label}: пропущено, ще виконується`);
		}

		isAnalyticsRunning = true;
		const startTime = Date.now();

		rebuild(days)
			.then(() => {
				const duration = Math.round((Date.now() - startTime) / 1000);
				console.log(`[analytics] ${label}: готово за ${duration}с`);
			})
			.catch((err) => {
				console.error(`[analytics] ${label}:`, err);
			})
			.finally(() => {
				isAnalyticsRunning = false;
			});
	};

	// ─── ПЛАНУВАННЯ CRON-ЗАДАЧ ───────────────────────

	// Запуск аналітики через 10 секунд після старту (початковий запуск)
	setTimeout(() => runAnalytics(7, "startup"), 10000);

	// Щогодини на 5-й хвилині
	cron.schedule("5 * * * *", () => runAnalytics(7, "hourly"), {
		timezone: "Europe/Kyiv",
	});

	// Щоденно о 03:20
	cron.schedule("20 3 * * *", () => runAnalytics(45, "daily"), {
		timezone: "Europe/Kyiv",
	});

	// Щодня о 04:30 — продовження IG-токенів
	cron.schedule("30 4 * * *", () => igRefreshTick().catch((e) => console.error("[ig-refresh]", e)), {
		timezone: "Europe/Kyiv",
	});

	// ─── НАГАДУВАННЯ КАЛЕНДАРЯ ───────────────────────
	let isReminderRunning = false;

	// Щохвилини — розсилка нагадувань, що настали
	cron.schedule(
		"* * * * *",
		async () => {
			if (isReminderRunning) {
				return console.log("[calendar-reminder] пропущено, ще виконується");
			}

			isReminderRunning = true;
			try {
				await calendarReminderTick();
			} catch (err) {
				console.error("[calendar-reminder]", err);
			} finally {
				isReminderRunning = false;
			}
		},
		{
			timezone: "Europe/Kyiv",
		}
	);

	// Щоденно о 04:10 — чистка відпрацьованих рядків черги
	cron.schedule(
		"10 4 * * *",
		async () => {
			try {
				await calendarReminderCleanup();
				console.log("[calendar-reminder] чистка черги готова");
			} catch (err) {
				console.error("[calendar-reminder cleanup]", err);
			}
		},
		{
			timezone: "Europe/Kyiv",
		}
	);
});
