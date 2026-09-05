/**
 * =====================================================
 * INSTAGRAM WEBHOOK — прийом подій від Meta
 * GET  /instagram/webhook  → верифікація (hub.challenge)
 * POST /instagram/webhook  → події (перевірка підпису + розбір + збереження)
 * ВАЖЛИВО: монтується в server.js ДО bodyParser (потрібне сире тіло).
 * =====================================================
 */
const express = require("express");
const fs = require("fs");
const path = require("path");
const router = express.Router();

const connection_pool = require("../../../config/database/connection_pool");
const logging = require("../../../logging/logging");
const { getIO } = require("../../../controllers/socket/socket");
const io = getIO();

const notifications = require("../../../controllers/notifications/index");

const { prefix, deriveChatId, verifySignature, getTokenByIgId, fetchIgProfile, sendText } = require("../../../controllers/contact-center/instagram/instagram");

const VERIFY_TOKEN = process.env.IG_VERIFY_TOKEN || "";

// ── Мапа типів вкладень Instagram → наші type_message ──
const ATTACH_TYPE = { image: "photo", video: "video", audio: "audio", file: "document", share: "share", story_mention: "story_mention", ig_reel: "video" };

// ================================================================
// GET — верифікація webhook (Meta шле один раз при підписці)
// ================================================================
router.get("/instagram/webhook", (req, res) => {
	const mode = req.query["hub.mode"];
	const token = req.query["hub.verify_token"];
	const challenge = req.query["hub.challenge"];

	console.log(mode);
	console.log(token);
	console.log(challenge);

	if (mode === "subscribe" && token === VERIFY_TOKEN) {
		return res.status(200).send(challenge);
	}
	return res.sendStatus(403);
});

// ================================================================
// POST — прийом подій
// express.raw дає req.body як Buffer → перевіряємо підпис, тоді парсимо.
// ================================================================
router.post("/instagram/webhook", express.raw({ type: "*/*" }), async (req, res) => {
	console.log("[ig-webhook] POST отримано, підпис:", req.get("x-hub-signature-256") ? "є" : "НЕМА");
	// 1) Підпис
	if (!verifySignature(req.body, req.get("x-hub-signature-256"))) {
		console.warn("[ig-webhook] ПІДПИС НЕ ПРОЙШОВ — відкинуто 403");
		return res.sendStatus(403);
	}
	console.log("[ig-webhook] підпис OK, тіло:", req.body.toString("utf8").slice(0, 500));

	// 2) Миттєве підтвердження (інакше Meta вимкне webhook)
	res.sendStatus(200);

	// 3) Розбір — асинхронно, помилки не валять відповідь
	let payload;
	try {
		payload = JSON.parse(req.body.toString("utf8"));
	} catch (e) {
		return logging.error(e);
	}
	if (payload.object !== "instagram") return;

	for (const entry of payload.entry || []) {
		const igId = String(entry.id); // ← який акаунт отримав повідомлення
		const events = entry.messaging || [];
		for (const ev of events) {
			processEvent(igId, ev).catch((err) => {
				logging.error(err);
				console.error("[instagram] processEvent:", err.message);
			});
		}
	}
});

// ================================================================
// Обробка одного messaging-івенту
// ================================================================
async function processEvent(igId, ev) {
	// Реакції/read/postback поки ігноруємо — беремо лише повідомлення
	if (!ev.message) return;

	const igsid = String(ev.sender?.id || "");
	if (!igsid) return;

	// Echo нашого ж вихідного повідомлення — не дублюємо в стрічці клієнта
	const isEcho = ev.message.is_echo ? 1 : 0;
	if (isEcho) return; // вихідні ми вже пишемо самі при відправці (Етап 3)

	const chat_id = deriveChatId(igId, igsid);
	const mid = String(ev.message.mid || "");
	const tsMs = Number(ev.timestamp) || Date.now();
	const date = toMysqlDate(new Date(tsMs));

	// Резолвимо токен акаунта (для профілю/медіа). Якщо акаунт не наш/вимкнений — виходимо.
	let token = null;
	let idToken = null;
	try {
		const resolved = await getTokenByIgId(igId);
		token = resolved.token;
		idToken = resolved.idToken;
	} catch (e) {
		// ACCOUNT_UNAVAILABLE / ACCOUNT_INACTIVE — подія не для нас або бот вимкнено
		return;
	}

	// ── Тип і дані повідомлення ──
	let type_message = "text";
	let messageData = {};

	if (ev.message.text && (!ev.message.attachments || !ev.message.attachments.length)) {
		type_message = "text";
		messageData = { text: ev.message.text };
	} else if (ev.message.attachments && ev.message.attachments.length) {
		const att = ev.message.attachments[0];
		type_message = ATTACH_TYPE[att.type] || "other";
		const url = att.payload?.url || null;

		if (url && ["photo", "video", "audio", "document"].includes(type_message)) {
			// Завантажуємо медіа на диск. Тека = id рядка БД (див. нижче), тому
			// спершу вставляємо рядок, потім докачуємо. Для простоти качаємо у файл із mid-хешем.
			messageData = { text: null, caption: ev.message.text || null, remote_url: url };
		} else if (type_message === "share" || type_message === "story_mention") {
			messageData = { text: ev.message.text || null, url, payload: att.payload || null };
		} else {
			messageData = { text: ev.message.text || null, payload: att.payload || null };
		}
	} else {
		type_message = "other";
		messageData = { other: "Unsupported message type" };
	}

	// ── Прив'язка chat_id → акаунт + igsid ──
	await connection_pool.execute(
		`INSERT INTO ${prefix}instagram_chat_token (chat_id, ig_id, igsid, id_token)
         VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE ig_id = VALUES(ig_id), igsid = VALUES(igsid), id_token = VALUES(id_token)`,
		[chat_id, igId, igsid, idToken]
	);

	// ── Профіль клієнта (тягнемо один раз, якщо ще не знаємо імені) ──
	const [[known]] = await connection_pool.query(`SELECT first_name, username FROM ${prefix}instagram_message WHERE chat_id = ? AND first_name IS NOT NULL LIMIT 1`, [chat_id]);
	let first_name = known?.first_name || null;
	let username = known?.username || null;
	if (!first_name) {
		const prof = await fetchIgProfile(igsid, token);
		first_name = prof.name || prof.username || "Instagram User";
		username = prof.username || null;
	}

	// ── Розмова: гарантуємо + reopen, оновлюємо вікно 24h ──
	await ensureConversation(chat_id, true, date);

	// ── Виводимо з архіву (як у telegram) ──
	const [[archiveRow]] = await connection_pool.query(`SELECT chat_id FROM ${prefix}instagram_archive WHERE chat_id = ?`, [chat_id]);
	const wasArchived = !!archiveRow;
	await connection_pool.query(`DELETE FROM ${prefix}instagram_archive WHERE chat_id = ?`, [chat_id]);

	// ── Привітання (за робочим часом акаунта) ──
	// Вікно 24h тут завжди відкрите (клієнт щойно написав), тож sendText безпечний.
	try {
		const [[acc]] = await connection_pool.query(`SELECT working_hours FROM ${prefix}instagram_tokens WHERE id = ? LIMIT 1`, [idToken]);
		if (acc && acc.working_hours) {
			const wh = typeof acc.working_hours === "string" ? JSON.parse(acc.working_hours) : acc.working_hours;
			const now = new Date();
			const currentDay = (now.getDay() === 0 ? 7 : now.getDay()).toString();
			const isWorking = Array.isArray(wh[currentDay]) && wh[currentDay].includes(now.getHours());

			const [[ct]] = await connection_pool.query(`SELECT greeted FROM ${prefix}instagram_chat_token WHERE chat_id = ? LIMIT 1`, [chat_id]);
			const greeted = ct?.greeted ?? 0;

			// Instagram НЕ передає language_code → беремо мову за замовчуванням.
			const langId = 1;

			let greetingType = null;
			if (!isWorking) {
				if (greeted !== 1) greetingType = 1; // поза робочим часом
			} else {
				if (wasArchived || greeted === 0 || greeted === 1) greetingType = 2; // привітання
			}

			if (greetingType) {
				const [[greeting]] = await connection_pool.query(`SELECT title, text FROM ${prefix}instagram_greeting WHERE id_lang = ? AND type = ? LIMIT 1`, [langId, greetingType]);
				if (greeting && token) {
					const body = greeting.title ? `${greeting.title}\n${greeting.text || ""}` : greeting.text || "";
					await sendText(token, igsid, body).catch((e) => logging.error(e));
					await connection_pool.query(`UPDATE ${prefix}instagram_chat_token SET greeted = ? WHERE chat_id = ?`, [greetingType, chat_id]);
				}
			}
		}
	} catch (e) {
		logging.error(e);
	}

	// ── Зберігаємо повідомлення (INSERT IGNORE по uq_mid — дедуплікація) ──
	const [ins] = await connection_pool.query(
		`INSERT IGNORE INTO ${prefix}instagram_message
           (message_id, chat_id, first_name, last_name, username, is_echo, date, message, type_message)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		[mid, chat_id, first_name, null, username, 0, date, JSON.stringify(messageData), type_message]
	);
	if (!ins.insertId && !ins.affectedRows) return; // дубль webhook — тихо виходимо
	if (ins.affectedRows === 0) return; // IGNORE спрацював на дублі mid

	const rowId = ins.insertId;

	// ── Докачуємо медіа у теку за id рядка (безпечно для ФС) ──
	if (messageData.remote_url) {
		try {
			const ext = guessExt(messageData.remote_url, type_message);
			const fileName = `${rowId}${ext}`;
			const saveDir = path.join("assets", "contact-center", "instagram", chat_id, "client", String(rowId));
			fs.mkdirSync(saveDir, { recursive: true });

			// URL медіа Instagram вимагає access_token акаунта, інакше CDN віддає HTML-заглушку
			await downloadFileAuth(messageData.remote_url, path.join(saveDir, fileName), token);

			messageData.text = fileName;
			delete messageData.remote_url;
			await connection_pool.query(`UPDATE ${prefix}instagram_message SET message = ? WHERE id = ?`, [JSON.stringify(messageData), rowId]);
		} catch (e) {
			logging.error(e);
		}
	}

	// ── Лічильники + socket emit (дзеркало твого updateUnreadAndEmit) ──
	await updateUnreadAndEmit({ chat_id, rowId, mid, first_name, username, messageData, type_message, date });
}

// ================================================================
// Розмова: єдиний стан + вікно 24h
// ================================================================
async function ensureConversation(chat_id, reopen, date) {
	await connection_pool.query(
		`INSERT INTO ${prefix}instagram_conversations (chat_id, status, last_inbound_at, date_add)
         VALUES (?, 'open', ?, NOW())
         ON DUPLICATE KEY UPDATE last_inbound_at = VALUES(last_inbound_at)`,
		[chat_id, date]
	);
	if (reopen) {
		await connection_pool.query(
			`UPDATE ${prefix}instagram_conversations
                SET status = 'open', resolved_at = NULL, archived_at = NULL, date_edit = NOW()
              WHERE chat_id = ? AND status IN ('resolved','archived')`,
			[chat_id]
		);
	}
}

// ================================================================
// Лічильники непрочитаних + emit (адаптація telegram updateUnreadAndEmit)
// ================================================================
async function updateUnreadAndEmit({ chat_id, rowId, mid, first_name, username, messageData, type_message, date }) {
	// Єдине сховище нотифікацій (спільна подія, персональне прочитання окремо)
	try {
		const notifData = {
			channel: "instagram",
			chat_id,
			site_id: "",
			name: first_name,
			message: messageData?.text ? String(messageData.text).slice(0, 500) : messageData?.caption ? String(messageData.caption).slice(0, 500) : "",
			last_at: date,
		};
		await connection_pool.query(`INSERT INTO ${prefix}notifications (type, data, is_read, \`groups\`, date_add) VALUES (2, CAST(? AS JSON), 0, 0, NOW())`, [JSON.stringify(notifData)]);
	} catch (e) {
		logging.error(e);
	}

	const [[managerRow]] = await connection_pool.query(`SELECT id_manager FROM ${prefix}instagram_conversations WHERE chat_id = ? LIMIT 1`, [chat_id]);

	const io_message = { chat_id, name: first_name, message_id: rowId, mid, message: messageData.text, caption: messageData.caption, type_message, date };
	const contactCenterBase = { chat_id, first_name, last_name: null, channel: "instagram", message: messageData.text || messageData.caption || "", date };

	if (managerRow && managerRow.id_manager != null) {
		const managerId = managerRow.id_manager;
		await connection_pool.query(
			`INSERT INTO ${prefix}instagram_unread (chat_id, manager_id, count) VALUES (?, ?, 1)
             ON DUPLICATE KEY UPDATE count = count + 1`,
			[chat_id, managerId]
		);
		const [[unread]] = await connection_pool.query(`SELECT count FROM ${prefix}instagram_unread WHERE chat_id = ? AND manager_id = ?`, [chat_id, managerId]);
		io.to(`io_manager_${managerId}`).emit("io_alert_contact_center", { ...contactCenterBase, unique_chat_id_count: unread?.count ?? 1, status: 1 });
		// ← у відкриту переписку теж (щоб повідомлення підвантажувалось без оновлення)
		io.to(`io_alert_instagram_${chat_id}`).emit(`io_alert_instagram_${chat_id}`, { ...io_message, unique_chat_id_count: unread?.count ?? 1 });
	} else {
		const [managers] = await connection_pool.query(`SELECT id FROM ${prefix}users WHERE active = 1 AND id IS NOT NULL`);
		if (!managers.length) return;
		await Promise.all(managers.map((m) => connection_pool.query(`INSERT INTO ${prefix}instagram_unread (chat_id, manager_id, count) VALUES (?, ?, 1) ON DUPLICATE KEY UPDATE count = count + 1`, [chat_id, m.id])));
		await Promise.all(
			managers.map(async (m) => {
				const [[unread]] = await connection_pool.query(`SELECT count FROM ${prefix}instagram_unread WHERE chat_id = ? AND manager_id = ?`, [chat_id, m.id]);
				io.to(`io_manager_${m.id}`).emit("io_alert_contact_center", { ...contactCenterBase, unique_chat_id_count: unread?.count ?? 1, status: 0 });
			})
		);
		io.to(`io_alert_instagram_${chat_id}`).emit(`io_alert_instagram_${chat_id}`, { ...io_message, unique_chat_id_count: 1 });
	}

	// ── Розсилка через notify() по отримувачах акаунта ──
	try {
		const [[acc]] = await connection_pool.query(`SELECT id, chat_id AS tg_chat_id, topic, topic_id, notify_active FROM ${prefix}instagram_tokens WHERE id = ? LIMIT 1`, [idToken]);
		if (acc && Number(acc.notify_active) === 1) {
			const text = messageData?.text ? String(messageData.text).slice(0, 500) : messageData?.caption ? String(messageData.caption).slice(0, 500) : "";
			const basePayload = {
				title: first_name,
				message: text,
				url: `/contact-center/instagram/${chat_id}/`,
				chat_id,
				message_id: rowId,
				channel: "instagram",
				date,
			};

			const [recipients] = await connection_pool.query(`SELECT kind, ref FROM ${prefix}instagram_notify_recipients WHERE id_token = ?`, [acc.id]);
			for (const r of recipients) {
				if (r.kind === "crm_user") {
					const [[u]] = await connection_pool.query(`SELECT count FROM ${prefix}instagram_unread WHERE chat_id = ? AND manager_id = ?`, [chat_id, Number(r.ref)]);
					await notifications
						.notify({
							type: "instagram.msg",
							audience: { user: Number(r.ref) },
							channels: ["inapp"],
							collapseKey: `instagram:${chat_id}`,
							payload: { ...basePayload, count: (u && u.count) || 1 },
						})
						.catch((e) => logging.error(e));
				} else if (r.kind === "crm_group") {
					const [[g]] = await connection_pool.query(`SELECT MAX(count) AS count FROM ${prefix}instagram_unread WHERE chat_id = ?`, [chat_id]);
					await notifications
						.notify({
							type: "instagram.msg",
							audience: { group: Number(r.ref) },
							channels: ["inapp"],
							collapseKey: `instagram:${chat_id}`,
							payload: { ...basePayload, count: (g && g.count) || 1 },
						})
						.catch((e) => logging.error(e));
				}
			}
		}
	} catch (e) {
		logging.error(e);
	}
}

// ── дрібні хелпери ──
const pad = (n) => String(n).padStart(2, "0");
const toMysqlDate = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;

function guessExt(url, type) {
	const clean = url.split("?")[0];
	const ext = path.extname(clean);
	if (ext) return ext;
	return type === "photo" ? ".jpg" : type === "video" ? ".mp4" : type === "audio" ? ".mp3" : "";
}

// Завантаження медіа Instagram з Authorization: Bearer (обов'язково для CDN)
async function downloadFileAuth(fileUrl, savePath, token, redirects = 0) {
	if (redirects > 5) throw new Error("Забагато редіректів");

	const resp = await fetch(fileUrl, {
		headers: { Authorization: "Bearer " + token },
		redirect: "manual", // редіректи обробляємо самі, щоб зберегти заголовок
	});

	// редірект — йдемо за location з тим самим заголовком
	if (resp.status >= 300 && resp.status < 400) {
		const loc = resp.headers.get("location");
		if (!loc) throw new Error("Редірект без location");
		const next = new URL(loc, fileUrl).toString();
		return downloadFileAuth(next, savePath, token, redirects + 1);
	}

	if (resp.status !== 200) {
		throw new Error("HTTP " + resp.status + " при завантаженні медіа");
	}

	const ctype = resp.headers.get("content-type") || "";
	if (ctype.includes("text/html")) {
		throw new Error("CDN повернув HTML замість медіа (доступ не надано)");
	}

	const buf = Buffer.from(await resp.arrayBuffer());
	fs.writeFileSync(savePath, buf);
}

module.exports = router;
