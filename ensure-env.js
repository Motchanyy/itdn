const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const ENV_PATH = path.join(__dirname, ".env");

// Генеруються самі — користувач не чіпає
const AUTO = {
	JWT_SECRET: { gen: () => crypto.randomBytes(64).toString("hex"), comment: "Підпис access-JWT. Зміна = розлогінення всіх. НЕ ЧІПАТИ." },
	JWT_REFRESH_SECRET: { gen: () => crypto.randomBytes(64).toString("hex"), comment: "Підпис refresh-JWT. Окремий від access. НЕ ЧІПАТИ." },
	TFA_ENC_KEY: { gen: () => crypto.randomBytes(32).toString("hex"), comment: "Шифрування 2FA у БД. Зміна = 2FA всіх злетить. НЕ ЧІПАТИ." },
	APP_ENCRYPTION_KEY: { gen: () => crypto.randomBytes(32).toString("hex"), comment: "Шифрування токенів інтеграцій у БД. НЕ ЧІПАТИ." },
	WEBCHAT_FILE_SECRET: { gen: () => crypto.randomBytes(48).toString("hex"), comment: "Підпис посилань на файли веб-чату. НЕ ЧІПАТИ." },
	SESSION_SECRET: { gen: () => crypto.randomBytes(48).toString("hex"), comment: "Підпис серверних сесій (express-session). НЕ ЧІПАТИ." },
};

// Заготовки з дефолтами/підказками — користувач редагує тут
const USER = {
	PORT: { def: "3000", hint: "Порт сервера" },
	APP_URL: { def: "", hint: "URL системи" },
	DB_PREFIX: { def: "gc_", hint: "Префікс таблиць БД" },
	INVITE_TTL_HOURS: { def: "72", hint: "Термін дії запрошення, годин" },
	RESET_TTL_MINUTES: { def: "30", hint: "Термін дії скидання пароля, хвилин" },
	TELEGRAM_TOKEN_KEY: { def: "", hint: "Токен Telegram-бота від @BotFather" },
	MAIL_HOST: { def: "", hint: "SMTP-сервер, напр. smtp.gmail.com" },
	MAIL_PORT: { def: "587", hint: "SMTP-порт (587 або 465)" },
	MAIL_USER: { def: "", hint: "SMTP-логін (email)" },
	MAIL_PASS: { def: "", hint: "SMTP-пароль або app-password" },
	MAIL_FROM: { def: "", hint: "Адреса відправника" },
};

function parseExisting() {
	if (!fs.existsSync(ENV_PATH)) return {};
	const out = {};
	for (const line of fs.readFileSync(ENV_PATH, "utf8").split("\n")) {
		const m = line.match(/^\s*([A-Z0-9_]+)\s*=/);
		if (m) out[m[1]] = true;
	}
	return out;
}

function ensureEnv() {
	const existing = parseExisting();
	const blocks = [];

	for (const [key, { gen, comment }] of Object.entries(AUTO)) {
		if (!existing[key]) blocks.push(`# ${comment}\n${key}=${gen()}`);
	}
	for (const [key, { def, hint }] of Object.entries(USER)) {
		if (!existing[key]) blocks.push(`# ${hint}\n${key}=${def}`);
	}

	if (blocks.length > 0) {
		const prefix = fs.existsSync(ENV_PATH) ? "\n" : "# === GROWTH CONTOUR — усі доступи в цьому файлі ===\n\n";
		fs.appendFileSync(ENV_PATH, prefix + blocks.join("\n\n") + "\n", { mode: 0o600 });
		fs.chmodSync(ENV_PATH, 0o600);
		console.log(`[env] додано полів: ${blocks.length}`);
	} else {
		console.log("[env] всі поля на місці");
	}

	process.loadEnvFile(ENV_PATH);
}

module.exports = { ensureEnv };
if (require.main === module) ensureEnv();
