/**
 * ===================================================================
 * ФАЙЛ: controllers/authorization/tfa_settings.js
 * ОПИС: Налаштування 2FA — узгоджено з helpers/tfa.js та crypto_tfa.js
 * ===================================================================
 */

const db = require("../../config/database/connection_pool");
const bcrypt = require("bcrypt");
const tfa = require("../../helpers/tfa");
const { encryptSecret } = require("../../helpers/crypto_tfa");

// ─── Конфігурація ────────────────────────────────────────────────────────────
const config = require("../../config/config");
const configDatabase = config.get("configDatabase");
const prefix = configDatabase.prefix;
// ─── Конфігурація ────────────────────────────────────────────────────────────

const tfaSettingsControllers = {
	// Статус 2FA
	status: async (req, res) => {
		try {
			const userId = req.user.userId;
			const [rows] = await db.execute(`SELECT tfa_enabled FROM ${prefix}users WHERE id = ?`, [userId]);
			if (rows.length === 0) return res.status(404).json({ status: "error", message: "User not found" });
			res.json({ status: "success", data: { enabled: rows[0].tfa_enabled === 1 } });
		} catch (error) {
			console.error("[TFA STATUS ERROR]:", error);
			res.status(500).json({ status: "error", message: "Server error" });
		}
	},

	// Ініціалізація: генерує секрет, шифрує його у pending, віддає QR
	init: async (req, res) => {
		try {
			const userId = req.user.userId;
			const [rows] = await db.execute(`SELECT email, tfa_enabled FROM ${prefix}users WHERE id = ?`, [userId]);
			if (rows.length === 0) return res.status(404).json({ status: "error", message: "User not found" });
			if (rows[0].tfa_enabled === 1) return res.status(400).json({ status: "error", message: "2FA вже увімкнено" });

			const secret = tfa.generateSecret();
			const otpauthUrl = tfa.buildOtpauthUrl(rows[0].email, secret);
			const qrDataUrl = await tfa.buildQrDataUrl(otpauthUrl);

			// У БД зберігаємо ЗАШИФРОВАНИЙ секрет як pending
			await db.execute(`UPDATE ${prefix}users SET tfa_secret_pending = ? WHERE id = ?`, [encryptSecret(secret), userId]);

			// Клієнту віддаємо plaintext-секрет лише для показу/ручного вводу і QR
			res.json({ status: "success", data: { secret, qr: qrDataUrl } });
		} catch (error) {
			console.error("[TFA INIT ERROR]:", error);
			res.status(500).json({ status: "error", message: "Server error" });
		}
	},

	// Підтвердження: перевіряє код проти pending-секрету, вмикає 2FA, видає backup-коди
	confirm: async (req, res) => {
		try {
			const userId = req.user.userId;
			const code = tfa.normalizeCode(req.body.code);
			if (!code) return res.status(400).json({ status: "error", message: "Code required" });

			const [rows] = await db.execute(`SELECT tfa_secret_pending FROM ${prefix}users WHERE id = ?`, [userId]);
			const pending = rows[0] && rows[0].tfa_secret_pending;
			if (!pending) return res.status(400).json({ status: "error", message: "No pending secret" });

			// Реальна перевірка TOTP (lastStep=0 — на етапі підтвердження anti-replay не потрібен)
			const result = tfa.verifyTotp(pending, code, 0);
			if (!result.ok) return res.status(400).json({ status: "invalid", message: "Invalid code" });

			// Вмикаємо 2FA: pending → secret, піднімаємо token_version (розлогінити інші сесії)
			await db.execute(
				`UPDATE ${prefix}users
				 SET tfa_secret = tfa_secret_pending, tfa_secret_pending = NULL,
				     tfa_enabled = 1, tfa_last_step = ?, token_version = token_version + 1
				 WHERE id = ?`,
				[result.step, userId]
			);

			// Генеруємо backup-коди (показуємо один раз)
			const codes = tfa.generateBackupCodes();
			await db.execute(`DELETE FROM ${prefix}users_tfa_backup_codes WHERE id_user = ?`, [userId]);
			const values = codes.map((c) => [userId, tfa.hashBackupCode(c)]);
			await db.query(`INSERT INTO ${prefix}users_tfa_backup_codes (id_user, code_hash) VALUES ?`, [values]);

			res.json({ status: "success", message: "2FA enabled", data: { backup_codes: codes } });
		} catch (error) {
			console.error("[TFA CONFIRM ERROR]:", error);
			res.status(500).json({ status: "error", message: "Server error" });
		}
	},

	// Вимкнення: ВИМАГАЄ пароль + діючий код 2FA (або backup)
	disable: async (req, res) => {
		try {
			const userId = req.user.userId;
			const { password } = req.body;
			const code = tfa.normalizeCode(req.body.code);
			if (!password || !code) return res.status(400).json({ status: "error", message: "Потрібні пароль і код 2FA" });

			const [rows] = await db.execute(
				`SELECT password, tfa_secret, tfa_last_step FROM ${prefix}users WHERE id = ?`,
				[userId]
			);
			if (rows.length === 0) return res.status(404).json({ status: "error", message: "User not found" });

			const ok = await bcrypt.compare(password, rows[0].password);
			if (!ok) return res.status(401).json({ status: "invalid", message: "Невірний пароль" });

			// Перевіряємо код (TOTP або backup)
			let codeOk = false;
			if (tfa.isValidBackupFormat(code)) {
				const [b] = await db.execute(
					`SELECT id FROM ${prefix}users_tfa_backup_codes WHERE id_user = ? AND code_hash = ? AND used_at IS NULL LIMIT 1`,
					[userId, tfa.hashBackupCode(code)]
				);
				codeOk = b.length > 0;
			} else {
				codeOk = tfa.verifyTotp(rows[0].tfa_secret, code, rows[0].tfa_last_step).ok;
			}
			if (!codeOk) return res.status(401).json({ status: "invalid", message: "Невірний код 2FA" });

			await db.execute(
				`UPDATE ${prefix}users
				 SET tfa_enabled = 0, tfa_secret = NULL, tfa_secret_pending = NULL,
				     tfa_last_step = 0, token_version = token_version + 1
				 WHERE id = ?`,
				[userId]
			);
			await db.execute(`DELETE FROM ${prefix}users_tfa_backup_codes WHERE id_user = ?`, [userId]);

			res.json({ status: "success", message: "2FA disabled" });
		} catch (error) {
			console.error("[TFA DISABLE ERROR]:", error);
			res.status(500).json({ status: "error", message: "Server error" });
		}
	},

	// Перегенерація backup-кодів (вимагає діючий код 2FA)
	regenerateBackupCodes: async (req, res) => {
		try {
			const userId = req.user.userId;
			const code = tfa.normalizeCode(req.body.code);
			if (!code) return res.status(400).json({ status: "error", message: "Потрібен код 2FA" });

			const [rows] = await db.execute(
				`SELECT tfa_secret, tfa_last_step, tfa_enabled FROM ${prefix}users WHERE id = ?`,
				[userId]
			);
			if (rows.length === 0 || rows[0].tfa_enabled !== 1) {
				return res.status(400).json({ status: "error", message: "2FA не увімкнено" });
			}
			if (!tfa.verifyTotp(rows[0].tfa_secret, code, rows[0].tfa_last_step).ok) {
				return res.status(401).json({ status: "invalid", message: "Невірний код 2FA" });
			}

			const codes = tfa.generateBackupCodes();
			await db.execute(`DELETE FROM ${prefix}users_tfa_backup_codes WHERE id_user = ?`, [userId]);
			const values = codes.map((c) => [userId, tfa.hashBackupCode(c)]);
			await db.query(`INSERT INTO ${prefix}users_tfa_backup_codes (id_user, code_hash) VALUES ?`, [values]);

			res.json({ status: "success", data: { backup_codes: codes } });
		} catch (error) {
			console.error("[TFA BACKUP ERROR]:", error);
			res.status(500).json({ status: "error", message: "Server error" });
		}
	},
};

module.exports = tfaSettingsControllers;