/**
 * =====================================================
 * INSTAGRAM — CRM-роути (Етап 3: відправка)
 * Підключається в server.js разом з рештою маршрутів (після bodyParser).
 * =====================================================
 */
const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const multer = require("multer");
const router = express.Router();

const connection_pool = require("../../../config/database/connection_pool");
const logging = require("../../../logging/logging");
const authorizationControllers = require("../../../controllers/authorization/authorization");
const { getIO } = require("../../../controllers/socket/socket");
const io = getIO();

const { prefix, getSendContextByChatId, sendText, sendAttachment, getAccountStatusByChatId, buildAuthUrl, exchangeCode, toLongLived, refreshLongLived, fetchSelf, encryptToken, validateManualToken } = require("../../../controllers/contact-center/instagram/instagram");

const PUBLIC_BASE = (process.env.IG_PUBLIC_BASE || "").replace(/\/+$/, "");

const APP_ID = process.env.IG_APP_ID || "";
const REDIRECT_URI = process.env.IG_REDIRECT_URI || "";
const IG_SCOPES = ["instagram_business_basic", "instagram_business_manage_messages"].join(",");

const pad = (n) => String(n).padStart(2, "0");
const mysqlNow = () => {
	const d = new Date();
	return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
};
const displayNow = () => {
	const d = new Date();
	return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())} ${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()}`;
};

// Мапа наших type → тип вкладення Instagram
const IG_ATTACH = { photo: "image", video: "video", audio: "audio", file: "file" };

// ── Сторінка списку акаунтів (токенів) ──
router.get("/contact-center/settings/instagram/", authorizationControllers.isAuthenticated, (req, res) => {
	res.render("pages/contact-center/contact-center/instagram/settings", {
		i18n: res,
		user: req.user,
		header: { navbar: "contact-center" },
	});
});

// ── Сторінка редагування конкретного акаунта ──
router.get("/contact-center/settings/instagram/:id([0-9]+)", authorizationControllers.isAuthenticated, async (req, res) => {
	try {
		console.log(prefix);
		const [rows] = await connection_pool.query(`SELECT * FROM ${prefix}instagram_tokens WHERE id = ? LIMIT 1`, [req.params.id]);
		if (!rows.length) return res.status(404).send("Not Found");
		res.render("pages/contact-center/contact-center/instagram/edit", {
			i18n: res,
			user: req.user,
			ns: rows[0],
			header: { navbar: "contact-center" },
		});
	} catch (error) {
		logging.error(error);
		console.log(error);
		res.status(500).send("Internal Server Error");
	}
});

// ================================================================
// GET — сторінка переписки
// ================================================================
router.get("/contact-center/instagram/:id/", authorizationControllers.isAuthenticated, async (req, res) => {
	const chat_id = req.params.id;
	if (!/^[a-f0-9]{32}$/i.test(chat_id)) return res.redirect("/404");

	try {
		const [info] = await connection_pool.query(`SELECT first_name, last_name, username FROM ${prefix}instagram_message WHERE chat_id = ? LIMIT 1`, [chat_id]);
		if (!info.length) return res.redirect("/404");

		const [[conv]] = await connection_pool.query(`SELECT id_manager FROM ${prefix}instagram_conversations WHERE chat_id = ? LIMIT 1`, [chat_id]);

		let data_manager = 0;
		if (conv && conv.id_manager != null) {
			data_manager = Number(conv.id_manager) === Number(req.user.id) ? 1 : 2;
		}

		// Прочитання нотифікацій цього чату для цього менеджера
		try {
			await connection_pool.query(
				`INSERT IGNORE INTO ${prefix}notification_reads (notification_id, manager_id)
                 SELECT n.id, ? FROM ${prefix}notifications AS n
                 WHERE n.type = 2 AND JSON_UNQUOTE(JSON_EXTRACT(n.data, '$.chat_id')) = ?`,
				[req.user.id, chat_id]
			);
			await connection_pool.query(`DELETE FROM ${prefix}instagram_unread WHERE chat_id = ? AND manager_id = ?`, [chat_id, req.user.id]);
			await connection_pool.query(`UPDATE ${prefix}notif_inbox SET archived_at = NOW(3) WHERE user_id = ? AND collapse_key = ?`, [req.user.id, `instagram:${chat_id}`]);
		} catch (e) {
			logging.error(e);
		}

		const accStatus = await getAccountStatusByChatId(chat_id);

		res.render("pages/contact-center/contact-center/instagram/index", {
			i18n: res,
			user: req.user,
			data_instagram_chat_id: chat_id,
			data_instagram: info,
			data_manager,
			account_available: accStatus.available ? 1 : 0,
			account_status_reason: accStatus.reason || "",
			header: { navbar: "" },
		});
	} catch (error) {
		logging.error(error);
		res.status(500).send("Internal Server Error");
	}
});

// Тимчасове сховище state (проти CSRF). Для проду краще Redis/БД, тут — memory.
const oauthStates = new Map();

// ── 1) Старт підключення: віддаємо URL авторизації ──
router.post("/api/contact-center/instagram/oauth/start/", authorizationControllers.isAuthenticated, (req, res) => {
	try {
		if (typeof buildAuthUrl !== "function") {
			return res.status(500).json({ error: "buildAuthUrl не імпортовано з controllers/.../instagram" });
		}
		if (!process.env.IG_APP_ID || !process.env.IG_REDIRECT_URI) {
			return res.status(500).json({ error: "Не задано IG_APP_ID або IG_REDIRECT_URI у .env" });
		}
		const state = crypto.randomBytes(16).toString("hex");
		oauthStates.set(state, { uid: req.user.id, ts: Date.now() });
		for (const [k, v] of oauthStates) if (Date.now() - v.ts > 6e5) oauthStates.delete(k);
		res.json({ url: buildAuthUrl(state) });
	} catch (e) {
		logging.error(e);
		res.status(500).json({ error: e.message });
	}
});

// ── 2) Callback від Meta: code → long-lived → запис у БД ──
router.get("/api/contact-center/instagram/oauth/callback", async (req, res) => {
	const { code, state, error } = req.query;
	if (error) return res.redirect("/contact-center/settings/instagram/?err=denied");
	if (!code || !state || !oauthStates.has(state)) return res.redirect("/contact-center/settings/instagram/?err=state");
	oauthStates.delete(state);

	try {
		const short = await exchangeCode(String(code));
		const long = await toLongLived(short.token);
		const self = await fetchSelf(long.token);

		const enc = encryptToken(long.token);
		const expiresAt = new Date(Date.now() + long.expiresIn * 1000);
		const pad = (n) => String(n).padStart(2, "0");
		const exp = `${expiresAt.getFullYear()}-${pad(expiresAt.getMonth() + 1)}-${pad(expiresAt.getDate())} ${pad(expiresAt.getHours())}:${pad(expiresAt.getMinutes())}:${pad(expiresAt.getSeconds())}`;

		const weekHours = [9, 10, 11, 12, 13, 14, 15, 16, 17, 18];
		const defaultHours = JSON.stringify({ 1: weekHours, 2: weekHours, 3: weekHours, 4: weekHours, 5: weekHours });

		// upsert по ig_id: повторне підключення того самого акаунта = оновлення токена
		await connection_pool.query(
			`INSERT INTO ${prefix}instagram_tokens
                (ig_id, ig_user_id, username, token, token_expires_at, name, description,
                 color_text, color_background, icon, working_hours, active, notify_active, note, date_add, date_edit)
             VALUES (?, ?, ?, ?, ?, ?, ?, '#ffffff', '#e1306c', 'fa-brands fa-instagram', CAST(? AS JSON), 1, 0, '', NOW(), NOW())
             ON DUPLICATE KEY UPDATE token = VALUES(token), token_expires_at = VALUES(token_expires_at),
                 username = VALUES(username), active = 1, date_edit = NOW()`,
			[self.igId, self.igId, self.username, enc, exp, self.username || "Instagram", "@" + (self.username || ""), defaultHours]
		);

		res.redirect("/contact-center/settings/instagram/?ok=1");
	} catch (e) {
		logging.error(e);
		res.redirect("/contact-center/settings/instagram/?err=exchange");
	}
});

// ── Список акаунтів (для tabulator) ──
router.post("/api/contact-center/instagram/token-list/", authorizationControllers.isAuthenticated, async (req, res) => {
	try {
		const [rows] = await connection_pool.query(`SELECT id, name, username, active, notify_active, token_expires_at, date_add, date_edit FROM ${prefix}instagram_tokens`);
		const fmt = (v) => {
			if (!v) return v;
			const d = new Date(v);
			const p = (n) => String(n).padStart(2, "0");
			return `${p(d.getDate())}.${p(d.getMonth() + 1)}.${d.getFullYear()}, ${p(d.getHours())}:${p(d.getMinutes())}`;
		};
		res.json(rows.map((r) => ({ ...r, date_add: fmt(r.date_add), date_edit: fmt(r.date_edit), token_expires_at: fmt(r.token_expires_at) })));
	} catch (e) {
		logging.error(e);
		res.status(500).json({ error: "err" });
	}
});

// ── Активація/деактивація (без polling — просто прапорець active) ──
router.post("/api/contact-center/instagram/settings/token/toggle/", authorizationControllers.isAuthenticated, async (req, res) => {
	const id = parseInt(req.body.id, 10);
	const active = req.body.active ? 1 : 0;
	if (!id) return res.status(422).json({ status: "error", message: "id обов'язковий" });
	try {
		await connection_pool.query(`UPDATE ${prefix}instagram_tokens SET active = ?, date_edit = NOW() WHERE id = ?`, [active, id]);
		res.json({ status: "success", active });
	} catch (e) {
		logging.error(e);
		res.status(500).json({ status: "error" });
	}
});

// ── Видалення акаунта (чати лишаються, стають неробочими) ──
router.post("/api/contact-center/instagram/settings/token/delete/", authorizationControllers.isAuthenticated, async (req, res) => {
	const id = parseInt(req.body.id, 10);
	if (!id) return res.status(422).json({ status: "error", message: "id обов'язковий" });
	const conn = await connection_pool.getConnection();
	try {
		await conn.beginTransaction();
		await conn.query(`DELETE FROM ${prefix}instagram_notify_recipients WHERE id_token = ?`, [id]);
		await conn.query(`DELETE FROM ${prefix}instagram_tokens WHERE id = ?`, [id]);
		await conn.commit();
		res.json({ status: "success", message: "Акаунт видалено." });
	} catch (e) {
		await conn.rollback();
		logging.error(e);
		res.status(500).json({ status: "error" });
	} finally {
		conn.release();
	}
});

// ── Збереження налаштувань акаунта (name/notify/working_hours/recipients) ──
// Дзеркало telegram settings/save/ — токен НЕ редагується.
router.post("/api/contact-center/instagram/settings/save/", authorizationControllers.isAuthenticated, async (req, res) => {
	const conn = await connection_pool.getConnection();
	try {
		const b = req.body || {};
		const id = parseInt(b.id, 10);
		if (!id) return res.status(422).json({ status: "error", message: "id обов'язковий" });
		const workingHours = typeof b.working_hours === "string" ? b.working_hours : JSON.stringify(b.working_hours || {});

		await conn.beginTransaction();
		await conn.query(
			`UPDATE ${prefix}instagram_tokens
                SET name = ?, note = ?, active = ?, notify_active = ?,
                    chat_id = ?, topic = ?, topic_id = ?,
                    color_text = ?, color_background = ?, icon = ?,
                    working_hours = CAST(? AS JSON), date_edit = NOW()
              WHERE id = ?`,
			[b.name || "", b.note || "", b.active ? 1 : 0, b.notify_active ? 1 : 0, b.chat_id || "", b.topic ? 1 : 0, b.topic_id || "", b.color_text || "", b.color_background || "", b.icon || "", workingHours, id]
		);

		const allowed = new Set(["crm_user", "crm_group"]);
		const recipients = Array.isArray(b.recipients) ? b.recipients : [];
		const clean = recipients.filter((r) => r && allowed.has(r.kind) && String(r.ref || "").trim()).map((r) => [id, r.kind, String(r.ref).trim().slice(0, 64), null]);
		await conn.query(`DELETE FROM ${prefix}instagram_notify_recipients WHERE id_token = ?`, [id]);
		if (clean.length) await conn.query(`INSERT INTO ${prefix}instagram_notify_recipients (id_token, kind, ref, topic_id) VALUES ?`, [clean]);

		await conn.commit();
		res.json({ status: "success" });
	} catch (e) {
		await conn.rollback();
		logging.error(e);
		res.status(500).json({ status: "error", message: e.message });
	} finally {
		conn.release();
	}
});

// ================================================================
// POST — історія повідомлень чату
// ================================================================
router.post("/contact-center/instagram/", async (req, res) => {
	const { chat_id } = req.body;
	if (!/^[a-f0-9]{32}$/i.test(chat_id || "")) return res.status(400).send("bad chat_id");

	try {
		const [clientMessages] = await connection_pool.query(`SELECT * FROM ${prefix}instagram_message WHERE chat_id = ? ORDER BY id ASC`, [chat_id]);
		const [managerMessages] = await connection_pool.query(`SELECT * FROM ${prefix}instagram_message_manager WHERE chat_id = ? ORDER BY id ASC`, [chat_id]);

		const merged = [
			...clientMessages.map((row) => {
				const m = typeof row.message === "string" ? JSON.parse(row.message) : row.message;
				return {
					chat_id: row.chat_id,
					message_id: row.id,
					id_manager: null,
					date: new Date(row.date),
					formattedDate: formatDisplay(row.date),
					message: m.text,
					caption: m.caption || null,
					type_message: row.type_message,
				};
			}),
			...managerMessages.map((row) => ({
				chat_id: row.chat_id,
				message_id: row.id,
				id_manager: row.id_manager,
				date: new Date(row.date),
				formattedDate: formatDisplay(row.date),
				message: row.message,
				type_message: row.type_message,
			})),
		];

		merged.sort((a, b) => a.date - b.date);
		res.json(merged.map(({ date, ...rest }) => rest));
	} catch (error) {
		logging.error(error);
		res.status(500).send("Помилка при отриманні даних");
	}
});

// хелпер формату дати для показу
function formatDisplay(isoDate) {
	const d = new Date(isoDate);
	return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())} ${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()}`;
}

// ================================================================
// Взяти чат у роботу
// ================================================================
router.post("/api/contact-center/instagram/manager/assign/", authorizationControllers.isAuthenticated, async (req, res) => {
	const { chat_id } = req.body;
	const id_manager = req.user.id;
	if (!/^[a-f0-9]{32}$/i.test(chat_id || "")) return res.status(400).json({ message: "chat_id обов'язковий." });

	const conn = await connection_pool.getConnection();
	try {
		await conn.query(
			`INSERT INTO ${prefix}instagram_conversations (chat_id, status, date_add)
             VALUES (?, 'open', NOW()) ON DUPLICATE KEY UPDATE id = id`,
			[chat_id]
		);
		const [[conv]] = await conn.query(`SELECT id_manager FROM ${prefix}instagram_conversations WHERE chat_id = ? LIMIT 1`, [chat_id]);
		if (conv && conv.id_manager != null) {
			conn.release();
			return res.status(409).json({ message: "Цей чат вже має менеджера." });
		}

		await conn.beginTransaction();
		await conn.query(
			`UPDATE ${prefix}instagram_conversations
                SET id_manager = ?, status = 'open', resolved_at = NULL, archived_at = NULL, date_edit = NOW()
              WHERE chat_id = ?`,
			[id_manager, chat_id]
		);
		await conn.commit();
		res.status(200).json({ message: "Менеджера успішно призначено." });
	} catch (error) {
		await conn.rollback();
		logging.error(error);
		res.status(500).json({ message: "Помилка сервера." });
	} finally {
		conn.release();
	}
});

// ── Додати акаунт вручну по токену (без OAuth) ──
router.post("/api/contact-center/instagram/settings/token/create/", authorizationControllers.isAuthenticated, async (req, res) => {
	try {
		const rawToken = String((req.body || {}).token || "").trim();
		const name = String((req.body || {}).name || "").trim();
		if (!rawToken) return res.status(422).json({ status: "error", message: "Вкажіть токен." });

		// Перевіряємо токен і дізнаємось ig_id (== entry.id webhook)
		let self;
		try {
			self = await validateManualToken(rawToken);
		} catch (e) {
			return res.status(422).json({ status: "error", message: "Токен недійсний: " + e.message });
		}

		const enc = encryptToken(rawToken);
		const weekHours = [9, 10, 11, 12, 13, 14, 15, 16, 17, 18];
		const defaultHours = JSON.stringify({ 1: weekHours, 2: weekHours, 3: weekHours, 4: weekHours, 5: weekHours });

		// Ручний токен: термін дії невідомий → лишаємо NULL (cron-refresh його не чіпатиме)
		const [ins] = await connection_pool.query(
			`INSERT INTO ${prefix}instagram_tokens
                (ig_id, ig_user_id, username, token, token_expires_at, name, description,
                 color_text, color_background, icon, working_hours, active, notify_active, note, date_add, date_edit)
             VALUES (?, ?, ?, ?, NULL, ?, ?, '#ffffff', '#e1306c', 'fa-brands fa-instagram', CAST(? AS JSON), 1, 0, '', NOW(), NOW())
             ON DUPLICATE KEY UPDATE token = VALUES(token), username = VALUES(username), active = 1, date_edit = NOW()`,
			[self.igId, self.igId, self.username, enc, name || self.username || "Instagram", "@" + (self.username || ""), defaultHours]
		);

		return res.json({ status: "success", id: ins.insertId, username: self.username });
	} catch (error) {
		logging.error(error);
		return res.status(500).json({ status: "error", message: "Помилка сервера." });
	}
});

// ================================================================
// Делегувати чат іншому менеджеру
// ================================================================
router.post("/api/contact-center/instagram/manager/delegate/", authorizationControllers.isAuthenticated, async (req, res) => {
	const { chat_id, id_manager } = req.body;
	if (!chat_id || !id_manager) return res.status(400).json({ message: "chat_id та id_manager обов'язкові." });

	try {
		const [[existing]] = await connection_pool.query(`SELECT id_manager FROM ${prefix}instagram_conversations WHERE chat_id = ? LIMIT 1`, [chat_id]);
		if (!existing) return res.status(404).json({ message: "Запис для цього чату не знайдено." });

		await connection_pool.query(`UPDATE ${prefix}instagram_conversations SET id_manager = ?, status = 'open', date_edit = NOW() WHERE chat_id = ?`, [id_manager, chat_id]);

		const [[chatInfo]] = await connection_pool.query(`SELECT first_name, last_name FROM ${prefix}instagram_message WHERE chat_id = ? ORDER BY id DESC LIMIT 1`, [chat_id]);
		const [[unreadRow]] = await connection_pool.query(`SELECT COALESCE(count,0) AS count FROM ${prefix}instagram_unread WHERE chat_id = ? AND manager_id = ?`, [chat_id, id_manager]).catch(() => [[{ count: 0 }]]);

		if (chatInfo) {
			io.to(`io_manager_${id_manager}`).emit("io_chat_delegated", {
				chat_id,
				channel: "instagram",
				first_name: chatInfo.first_name,
				last_name: chatInfo.last_name,
				count: unreadRow?.count ?? 0,
				status: 1,
			});
		}
		io.to(`io_manager_${req.user.id}`).emit("io_chat_removed", { chat_id, channel: "instagram" });

		res.status(200).json({ message: "Менеджера успішно змінено." });
	} catch (error) {
		logging.error(error);
		res.status(500).json({ message: "Помилка сервера." });
	}
});

// ================================================================
// Завершити діалог (resolved)
// ================================================================
router.post("/api/contact-center/instagram/resolve/", authorizationControllers.isAuthenticated, async (req, res) => {
	const { id_chat } = req.body;
	if (!id_chat || !/^[a-f0-9]{32}$/i.test(id_chat)) return res.status(400).json({ error: "Невірний формат id_chat" });
	try {
		await connection_pool.query(
			`INSERT INTO ${prefix}instagram_conversations (chat_id, status, resolved_at, date_add)
             VALUES (?, 'resolved', NOW(), NOW())
             ON DUPLICATE KEY UPDATE status = 'resolved', resolved_at = NOW(), date_edit = NOW()`,
			[id_chat]
		);
		io.to("io_alert_contact_center").emit("io_chat_resolved", { chat_id: id_chat, channel: "instagram" });
		res.status(200).json({ success: true });
	} catch (error) {
		logging.error(error);
		res.status(500).json({ error: "Помилка сервера" });
	}
});

// ================================================================
// Архівувати чат
// ================================================================
router.post("/api/contact-center/instagram/archive/", authorizationControllers.isAuthenticated, async (req, res) => {
	const conn = await connection_pool.getConnection();
	try {
		const { id_chat } = req.body;
		if (!id_chat || !/^[a-f0-9]{32}$/i.test(id_chat)) {
			conn.release();
			return res.status(400).json({ error: "Невірний формат id_chat" });
		}
		await conn.beginTransaction();
		await conn.query(
			`INSERT INTO ${prefix}instagram_conversations (chat_id, status, archived_at, date_add)
             VALUES (?, 'archived', NOW(), NOW())
             ON DUPLICATE KEY UPDATE status = 'archived', archived_at = NOW(), id_manager = NULL, date_edit = NOW()`,
			[id_chat]
		);
		await conn.query(`INSERT INTO ${prefix}instagram_archive (chat_id) VALUES (?) ON DUPLICATE KEY UPDATE chat_id = chat_id`, [id_chat]);
		await conn.query(`UPDATE ${prefix}instagram_chat_token SET greeted = 0 WHERE chat_id = ?`, [id_chat]);
		await conn.commit();

		io.to("io_alert_contact_center").emit("io_chat_archived", { chat_id: id_chat, channel: "instagram" });
		res.status(200).json({ success: true });
	} catch (error) {
		await conn.rollback();
		logging.error(error);
		res.status(500).json({ error: "Помилка сервера" });
	} finally {
		conn.release();
	}
});

// ================================================================
// Видалити чат (дані + нотифікації, акаунт-токен не чіпаємо)
// ================================================================
router.post("/api/contact-center/instagram/delete/", authorizationControllers.isAuthenticated, async (req, res) => {
	const conn = await connection_pool.getConnection();
	try {
		const { id_chat } = req.body;
		if (!id_chat || !/^[a-f0-9]{32}$/i.test(id_chat)) {
			conn.release();
			return res.status(400).json({ error: "Невірний формат id_chat" });
		}
		await conn.beginTransaction();
		await Promise.all(["instagram_message", "instagram_message_manager", "instagram_archive", "instagram_unread", "instagram_chat_token", "instagram_conversations"].map((t) => conn.query(`DELETE FROM ${prefix}${t} WHERE chat_id = ?`, [id_chat])));
		await conn.query(
			`DELETE r FROM ${prefix}notification_reads AS r
               INNER JOIN ${prefix}notifications AS n ON n.id = r.notification_id
             WHERE n.type = 2 AND JSON_UNQUOTE(JSON_EXTRACT(n.data, '$.chat_id')) = ?`,
			[id_chat]
		);
		await conn.query(`DELETE FROM ${prefix}notifications WHERE type = 2 AND JSON_UNQUOTE(JSON_EXTRACT(data, '$.chat_id')) = ?`, [id_chat]);
		await conn.commit();

		res.status(200).json({ success: true, message: "Дані успішно видалено" });
	} catch (error) {
		await conn.rollback();
		logging.error(error);
		res.status(500).json({ error: "Помилка сервера при видаленні даних" });
	} finally {
		conn.release();
	}
});

// ================================================================
// Медіатека чату
// ================================================================
router.get("/api/contact-center/instagram/:chat_id/media/", authorizationControllers.isAuthenticated, async (req, res) => {
	const { chat_id } = req.params;
	if (!/^[a-f0-9]{32}$/i.test(chat_id)) return res.status(400).json({ error: "Невірний формат chat_id" });

	try {
		const [clientMessages] = await connection_pool.query(
			`SELECT id, message, type_message, date, 'client' AS sender
               FROM ${prefix}instagram_message
              WHERE chat_id = ? AND type_message IN ('photo','video','document','audio','text')
              ORDER BY date DESC`,
			[chat_id]
		);
		const [managerMessages] = await connection_pool.query(
			`SELECT id, message, type_message, date, 'manager' AS sender
               FROM ${prefix}instagram_message_manager
              WHERE chat_id = ? AND type_message IN ('photo','video','file','audio','text')
              ORDER BY date DESC`,
			[chat_id]
		);

		const URL_REGEX = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
		const result = { photos: [], videos: [], files: [], audio: [], voice: [], gifs: [], links: [] };

		const allMessages = [...clientMessages.map((r) => ({ ...r, message: typeof r.message === "string" ? JSON.parse(r.message) : r.message })), ...managerMessages.map((r) => ({ ...r, message: { text: r.message } }))].sort((a, b) => new Date(b.date) - new Date(a.date));

		for (const msg of allMessages) {
			const { id, message, type_message, date, sender } = msg;
			const fd = formatDisplay(date);
			const basePath = `/assets/contact-center/instagram/${chat_id}/${sender}/${id}/`;

			switch (type_message) {
				case "photo":
					result.photos.push({ type: "photo", url: basePath + message.text, caption: message.caption || null, date: fd, sender });
					break;
				case "video":
					result.videos.push({ type: "video", url: basePath + message.text, date: fd, sender });
					break;
				case "document":
				case "file": {
					const fileName = message.text || "";
					const ext = path.extname(fileName).toLowerCase().replace(".", "");
					result.files.push({ url: basePath + fileName, name: fileName, size: message.size || null, ext: ext || "file", date: fd, sender });
					break;
				}
				case "audio":
					result.audio.push({ url: basePath + message.text, name: message.text || "audio", date: fd, sender });
					break;
				case "text": {
					const urls = (message.text || "").match(URL_REGEX);
					if (urls) urls.forEach((url) => result.links.push({ url, text: message.text, date: fd, sender }));
					break;
				}
			}
		}
		res.json(result);
	} catch (error) {
		logging.error(error);
		res.status(500).json({ error: "Помилка сервера" });
	}
});

// ================================================================
// Відправити ТЕКСТ менеджером
// ================================================================
router.post("/contact-center/instagram/:chat_id/", authorizationControllers.isAuthenticated, async (req, res) => {
	const chat_id = req.params.chat_id;
	const { message } = req.body;

	if (!/^[a-f0-9]{32}$/i.test(chat_id)) return res.status(400).json({ error: "Невірний формат chat_id" });
	if (!message || !String(message).trim()) return res.status(400).json({ error: "Порожнє повідомлення" });

	try {
		let ctx;
		try {
			ctx = await getSendContextByChatId(chat_id);
		} catch (e) {
			const msg = String(e.message || "");
			if (msg.startsWith("ACCOUNT_UNAVAILABLE") || msg.startsWith("ACCOUNT_INACTIVE")) {
				return res.status(409).json({ error: "ACCOUNT_UNAVAILABLE", message: "Акаунт цього чату вимкнено або видалено. Повідомлення не надіслано." });
			}
			throw e;
		}

		// Вікно 24h
		if (!ctx.windowOpen) {
			return res.status(409).json({ error: "WINDOW_CLOSED", message: "Минуло 24 години з останнього повідомлення клієнта. Instagram не дозволяє відповісти, доки клієнт не напише знову." });
		}

		let mid = null;
		try {
			mid = await sendText(ctx.token, ctx.igsid, message);
		} catch (e) {
			if (e.windowClosed) return res.status(409).json({ error: "WINDOW_CLOSED", message: "Вікно 24 години закрите." });
			throw e;
		}

		const dateStr = mysqlNow();
		await connection_pool.query(
			`INSERT INTO ${prefix}instagram_message_manager (id_manager, chat_id, mid, date, message, type_message)
             VALUES (?, ?, ?, ?, ?, ?)`,
			[req.user.id, chat_id, mid, dateStr, message, "text"]
		);

		res.json({ message, date: displayNow() });
	} catch (err) {
		logging.error(err);
		console.error("[instagram] send text:", err.message);
		res.status(500).json({ error: "Failed to send message" });
	}
});

// ================================================================
// Відправити ФАЙЛ менеджером (через публічний URL — вимога Instagram)
// ================================================================
router.post("/contact-center/instagram/:id/add-file/", authorizationControllers.isAuthenticated, async (req, res) => {
	const chat_id = req.params.id;
	if (!/^[a-f0-9]{32}$/i.test(chat_id)) return res.status(400).json({ error: "Невірний формат chat_id" });

	let ctx;
	try {
		ctx = await getSendContextByChatId(chat_id);
	} catch (e) {
		return res.status(409).json({ error: "ACCOUNT_UNAVAILABLE", message: "Акаунт недоступний." });
	}
	if (!ctx.windowOpen) {
		return res.status(409).json({ error: "WINDOW_CLOSED", message: "Минуло 24 години — відповісти файлом не можна, доки клієнт не напише." });
	}
	if (!PUBLIC_BASE) {
		return res.status(500).json({ error: "NO_PUBLIC_BASE", message: "Не налаштовано IG_PUBLIC_BASE — Instagram не зможе викачати файл." });
	}

	const upload = multer({ storage: multer.memoryStorage() }).single("file");
	upload(req, res, async (err) => {
		if (err) return res.status(500).send("Помилка завантаження файлу.");
		if (!req.file) return res.status(400).send("Файл не був завантажений.");

		const file = req.file;
		const type_message = file.mimetype.startsWith("image/") ? "photo" : file.mimetype.startsWith("video/") ? "video" : file.mimetype.startsWith("audio/") ? "audio" : "file";
		const dateStr = mysqlNow();

		try {
			// 1) Запис у БД (щоб мати id для теки)
			const [result] = await connection_pool.query(
				`INSERT INTO ${prefix}instagram_message_manager (id_manager, chat_id, date, message, type_message)
                 VALUES (?, ?, ?, ?, ?)`,
				[req.user.id, chat_id, dateStr, file.originalname, type_message]
			);
			const rowId = result.insertId;

			// 2) Зберігаємо файл у публічну теку
			const saveDir = path.join("assets", "contact-center", "instagram", chat_id, "manager", String(rowId));
			fs.mkdirSync(saveDir, { recursive: true });
			fs.writeFileSync(path.join(saveDir, file.originalname), file.buffer);

			// 3) Формуємо публічний URL і шлемо в Instagram
			const publicUrl = `${PUBLIC_BASE}/assets/contact-center/instagram/${chat_id}/manager/${rowId}/${encodeURIComponent(file.originalname)}`;
			let mid = null;
			try {
				mid = await sendAttachment(ctx.token, ctx.igsid, IG_ATTACH[type_message] || "file", publicUrl);
			} catch (e) {
				if (e.windowClosed) return res.status(409).json({ error: "WINDOW_CLOSED", message: "Вікно 24 години закрите." });
				throw e;
			}
			if (mid) await connection_pool.query(`UPDATE ${prefix}instagram_message_manager SET mid = ? WHERE id = ?`, [mid, rowId]);

			// 4) Socket emit у переписку
			io.to(`io_alert_instagram_${chat_id}`).emit(`io_alert_instagram_${chat_id}`, {
				chat_id,
				id_manager: req.user.id,
				message_id: rowId,
				message: file.originalname,
				type_message,
				date: displayNow(),
			});

			res.json({ success: true });
		} catch (error) {
			logging.error(error);
			console.error("[instagram] send file:", error.message);
			res.status(500).send("Помилка відправлення файлу.");
		}
	});
});

module.exports = router;
