const express = require("express");
const TelegramBot = require("node-telegram-bot-api");
const fs = require("fs");
const crypto = require("crypto");
const multer = require("multer");
const https = require("https");
const path = require("path");
const router = express.Router();

// Controllers
const authorizationControllers = require("../../../controllers/authorization/authorization");

// Notifications
const notifications = require("../../../controllers/notifications/index");
// END Notifications

// Конфігурація
const config = require("../../../config/config");
const configDatabase = config.get("configDatabase");
const telegramTokenKey = config.get("telegramTokenKey");
const prefix = configDatabase.prefix;

// Database connection
const connection_pool = require("../../../config/database/connection_pool");

// Логування
const logging = require("../../../logging/logging");

const { getIO } = require("../../../controllers/socket/socket");
const io = getIO();

// ================================================================
// ХЕЛПЕРИ
// ================================================================

/**
 * Шифрування chat_id для зберігання в БД
 */
const encrypt = (botId, tgChatId) => {
	const cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from("12345678901234567890123456789012"), Buffer.from("1234567890123456"));
	return cipher.update(`${botId}:${tgChatId}`, "utf8", "hex") + cipher.final("hex");
};

/**
 * Розшифрування chat_id (ідентифікатор чату, НЕ токен)
 */
const decrypt = (encrypted) => {
	const decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from("12345678901234567890123456789012"), Buffer.from("1234567890123456"));
	const raw = decipher.update(encrypted, "hex", "utf8") + decipher.final("utf8");
	const [botId, tgChatId] = raw.split(":");
	return { botId, tgChatId };
};

/**
 * Шифрування/розшифрування BOT-ТОКЕНА (AES-256-GCM, ключ з env).
 * Формат зберігання: iv:tag:cipher (усі hex). Токен ніде не світиться плейном.
 */
const TOKEN_KEY = Buffer.from(telegramTokenKey.telegramTokenKey, "hex");

const encryptToken = (plain) => {
	const iv = crypto.randomBytes(12);
	const cipher = crypto.createCipheriv("aes-256-gcm", TOKEN_KEY, iv);
	const enc = Buffer.concat([cipher.update(String(plain), "utf8"), cipher.final()]);
	const tag = cipher.getAuthTag();
	return `${iv.toString("hex")}:${tag.toString("hex")}:${enc.toString("hex")}`;
};

const decryptToken = (stored) => {
	const parts = String(stored).split(":");
	if (parts.length !== 3) throw new Error("Bad token format");
	const [ivHex, tagHex, dataHex] = parts;
	const decipher = crypto.createDecipheriv("aes-256-gcm", TOKEN_KEY, Buffer.from(ivHex, "hex"));
	decipher.setAuthTag(Buffer.from(tagHex, "hex"));
	return Buffer.concat([decipher.update(Buffer.from(dataHex, "hex")), decipher.final()]).toString("utf8");
};

/**
 * Форматування розміру файлу
 */
const formatFileSize = (bytes) => {
	const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
	if (bytes === 0) return "0 Bytes";
	const i = Math.floor(Math.log(bytes) / Math.log(1024));
	return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
};

/**
 * Форматування дати для відображення
 */
const formatDate = (isoDate) => {
	const dateObj = new Date(isoDate);
	const pad = (n) => String(n).padStart(2, "0");
	return `${pad(dateObj.getHours())}:${pad(dateObj.getMinutes())}:${pad(dateObj.getSeconds())} ${pad(dateObj.getDate())}.${pad(dateObj.getMonth() + 1)}.${dateObj.getFullYear()}`;
};

/**
 * Форматування "скільки часу пройшло"
 */
const formatTimePassed = (dateStr) => {
	const diffInSeconds = (new Date() - new Date(dateStr)) / 1000;
	if (diffInSeconds < 60) return "менше хвилини тому";
	if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} хвилин тому`;
	if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} годин тому`;
	return formatDate(dateStr);
};

/**
 * Завантаження файлу з Telegram і збереження на диск
 */
const downloadTelegramFile = (fileUrl, savePath) => {
	return new Promise((resolve, reject) => {
		const file = fs.createWriteStream(savePath);
		https
			.get(fileUrl, (response) => {
				response.pipe(file);
				file.on("finish", () => file.close(resolve));
			})
			.on("error", (error) => {
				fs.unlink(savePath, () => {});
				reject(error);
			});
	});
};

/**
 * Отримання токену бота по зашифрованому chat_id
 */
const getBotTokenByChatId = async (encryptedChatId) => {
	const [rows] = await connection_pool.execute(
		`SELECT t.token
         FROM ${prefix}telegram_chat_token ct
         JOIN ${prefix}telegram_tokens t
              ON t.active = 1
             AND (
                   (ct.bot_id IS NOT NULL AND t.bot_id = ct.bot_id)
                OR (ct.bot_id IS NULL AND t.id = ct.id_token)
                 )
         WHERE ct.chat_id = ?
         ORDER BY (ct.bot_id IS NOT NULL AND t.bot_id = ct.bot_id) DESC
         LIMIT 1`,
		[encryptedChatId]
	);
	if (!rows.length) throw new Error(`BOT_UNAVAILABLE:${encryptedChatId}`);
	return decryptToken(rows[0].token);
};

// Стан бота для чату: чи є активний токен (для індикації в переписці)
const getChatBotStatus = async (encryptedChatId) => {
	const [rows] = await connection_pool.execute(
		`SELECT t.id, t.name, t.active
         FROM ${prefix}telegram_chat_token ct
         LEFT JOIN ${prefix}telegram_tokens t
              ON (ct.bot_id IS NOT NULL AND t.bot_id = ct.bot_id)
              OR (ct.bot_id IS NULL AND t.id = ct.id_token)
         WHERE ct.chat_id = ?
         ORDER BY (t.active = 1) DESC
         LIMIT 1`,
		[encryptedChatId]
	);
	if (!rows.length || !rows[0].id) return { available: false, reason: "no_bot" };
	if (Number(rows[0].active) !== 1) return { available: false, reason: "inactive", name: rows[0].name };
	return { available: true, name: rows[0].name };
};

// ================================================================
// РОЗМОВИ (єдиний стан: open / resolved / archived + assignee)
// ================================================================

// Гарантуємо наявність розмови. Нове повідомлення клієнта → reopen із resolved/archived.
const ensureConversation = async (chat_id, reopen = false) => {
	await connection_pool.query(
		`INSERT INTO ${prefix}telegram_conversations (chat_id, status, date_add)
     VALUES (?, 'open', NOW())
     ON DUPLICATE KEY UPDATE id = id`,
		[chat_id]
	);
	if (reopen) {
		await connection_pool.query(
			`UPDATE ${prefix}telegram_conversations
          SET status = 'open', resolved_at = NULL, archived_at = NULL, date_edit = NOW()
        WHERE chat_id = ? AND status IN ('resolved','archived')`,
			[chat_id]
		);
	}
};

// ================================================================
// TELEGRAM БОТИ
// ================================================================

let bots = [];
let currentTokens = [];

const getTokensFromDB = async () => {
	try {
		const [rows] = await connection_pool.execute(`SELECT id, bot_id, token FROM ${prefix}telegram_tokens WHERE active = 1`);
		return rows
			.map((row) => {
				try {
					return { id: row.id, botId: row.bot_id, token: decryptToken(row.token) };
				} catch (e) {
					logging.error(e);
					return null;
				}
			})
			.filter(Boolean);
	} catch (e) {
		if (e.code === "ER_NO_SUCH_TABLE") {
			console.warn("[telegram] таблиці ще нема — пропускаю до заливки схеми");
			return [];
		}
		throw e;
	}
};

/**
 * Парсинг вхідного повідомлення — визначає тип і дані
 */
const parseIncomingMessage = async (msg, bot, token, encryptedChatId) => {
	if (msg.text) {
		return { type: "text", data: { text: msg.text } };
	}

	// Завантажує файл з Telegram і повертає дані повідомлення
	const downloadFile = async (fileId, subDir, getFileName, extra = {}) => {
		const fileInfo = await bot.getFile(fileId);
		const fileUrl = `https://api.telegram.org/file/bot${token}/${fileInfo.file_path}`;
		const extension = path.extname(fileInfo.file_path) || extra.defaultExt || "";
		const fileName = getFileName(fileId, extension, fileInfo);
		const savePath = path.join("assets", "contact-center", "telegram", encryptedChatId, "client", msg.message_id.toString());

		fs.mkdirSync(savePath, { recursive: true });
		await downloadTelegramFile(fileUrl, path.join(savePath, fileName));

		return fileName;
	};

	if (msg.photo) {
		const fileId = msg.photo[msg.photo.length - 1].file_id;
		const fileName = await downloadFile(fileId, "client", (id, ext) => `${id}${ext}`);
		return { type: "photo", data: { text: fileName, caption: msg.caption || null } };
	}

	if (msg.video) {
		const fileName = await downloadFile(msg.video.file_id, "client", (id, ext) => `${id}${ext}`);
		return { type: "video", data: { text: fileName } };
	}

	if (msg.document) {
		const fileId = msg.document.file_id;
		const fileInfo = await bot.getFile(fileId);
		const fileUrl = `https://api.telegram.org/file/bot${token}/${fileInfo.file_path}`;
		const savePath = path.join("assets", "contact-center", "telegram", encryptedChatId, "client", msg.message_id.toString());
		fs.mkdirSync(savePath, { recursive: true });
		await downloadTelegramFile(fileUrl, path.join(savePath, msg.document.file_name));
		return {
			type: "document",
			data: {
				text: msg.document.file_name,
				caption: msg.caption || null,
				size: formatFileSize(msg.document.file_size || 0),
			},
		};
	}

	if (msg.audio) {
		const fileName = await downloadFile(msg.audio.file_id, "client", (id, ext) => `${id}${ext}`);
		return { type: "audio", data: { text: fileName } };
	}

	if (msg.sticker) {
		const fileName = await downloadFile(msg.sticker.file_id, "client", (id, ext) => `${id}${ext}`, { defaultExt: ".webp" });
		return { type: "sticker", data: { text: fileName, caption: msg.caption || null } };
	}

	if (msg.voice) return { type: "voice", data: { voice: msg.voice } };
	if (msg.location) return { type: "location", data: { location: msg.location } };
	if (msg.contact) return { type: "contact", data: { text: msg.contact.phone_number } };
	if (msg.animation) return { type: "animation", data: { animation: msg.animation } };
	if (msg.video_note) return { type: "video_note", data: { video_note: msg.video_note } };
	if (msg.dice) return { type: "dice", data: { dice: msg.dice } };
	if (msg.venue) return { type: "venue", data: { venue: msg.venue } };
	if (msg.game) return { type: "game", data: { game: msg.game } };
	if (msg.invoice) return { type: "invoice", data: { invoice: msg.invoice } };
	if (msg.successful_payment) return { type: "successful_payment", data: { successful_payment: msg.successful_payment } };
	if (msg.pinned_message) return { type: "pinned_message", data: { pinned_message: msg.pinned_message } };

	return { type: "other", data: { other: "Unsupported message type" } };
};

/**
 * Оновлення персонального лічильника непрочитаних і emit socket події
 */
const updateUnreadAndEmit = async ({ chat_id, first_name, last_name, message_id, messageData, type_message, formattedDate, room_date, room_month, room_year, room_hours, room_minutes, room_seconds, archive, token, idToken }) => {
	const dateStr = `${room_hours}:${room_minutes}:${room_seconds} ${room_date}.${room_month}.${room_year}`;

	// Єдине сховище нотифікацій: одна подія на повідомлення (спільна для всіх менеджерів).
	// Персональне прочитання — через notification_reads (галочка окремо в кожного).
	try {
		const notifData = {
			channel: "telegram",
			chat_id,
			site_id: "",
			name: last_name ? `${first_name} ${last_name}` : first_name,
			message: messageData && messageData.text ? String(messageData.text).slice(0, 500) : "",
			last_at: `${room_year}-${room_month}-${room_date} ${room_hours}:${room_minutes}:${room_seconds}`,
		};
		await connection_pool.query(
			`INSERT INTO ${prefix}notifications (type, data, is_read, \`groups\`, date_add)
             VALUES (2, CAST(? AS JSON), 0, 0, NOW())`,
			[JSON.stringify(notifData)]
		);
	} catch (e) {
		logging.error(e);
		console.error("notifications insert (telegram):", e.message);
	}

	const [[managerRow]] = await connection_pool.query(`SELECT id_manager FROM ${prefix}telegram_conversations WHERE chat_id = ? LIMIT 1`, [chat_id]);

	const io_message = {
		chat_id,
		name: last_name ? `${first_name} ${last_name}` : first_name,
		message_id,
		message: messageData.text,
		caption: messageData.caption,
		type_message,
		size: messageData.size,
		date: dateStr,
		time_has_passed: formattedDate,
	};

	const contactCenterBase = {
		chat_id,
		first_name,
		last_name,
		message: messageData.text,
		date: dateStr,
		archive: archive ? "1" : "0",
	};

	if (managerRow && managerRow.id_manager != null) {
		// Чат має менеджера — лічильник тільки для нього
		const managerId = managerRow.id_manager;

		await connection_pool.query(
			`INSERT INTO ${prefix}telegram_unread (chat_id, manager_id, count)
             VALUES (?, ?, 1)
             ON DUPLICATE KEY UPDATE count = count + 1`,
			[chat_id, managerId]
		);

		const [[unread]] = await connection_pool.query(`SELECT count FROM ${prefix}telegram_unread WHERE chat_id = ? AND manager_id = ?`, [chat_id, managerId]);

		const count = unread?.count ?? 1;

		io.to(`io_manager_${managerId}`).emit("io_alert_contact_center", {
			...contactCenterBase,
			unique_chat_id_count: count,
			status: 1,
		});
	} else {
		// Чат вільний — лічильник для всіх активних менеджерів
		const [managers] = await connection_pool.query(`SELECT id FROM ${prefix}users WHERE active = 1 AND id IS NOT NULL`);
		if (!managers.length) return;

		// Збільшуємо лічильник для всіх паралельно
		await Promise.all(
			managers.map((m) =>
				connection_pool.query(
					`INSERT INTO ${prefix}telegram_unread (chat_id, manager_id, count)
                     VALUES (?, ?, 1)
                     ON DUPLICATE KEY UPDATE count = count + 1`,
					[chat_id, m.id]
				)
			)
		);

		// Кожному менеджеру емітимо його персональний лічильник
		await Promise.all(
			managers.map(async (m) => {
				const [[unread]] = await connection_pool.query(`SELECT count FROM ${prefix}telegram_unread WHERE chat_id = ? AND manager_id = ?`, [chat_id, m.id]);
				const count = unread?.count ?? 1;

				io.to(`io_manager_${m.id}`).emit("io_alert_contact_center", {
					...contactCenterBase,
					unique_chat_id_count: count,
					status: 0,
				});
			})
		);

		io.to(`io_alert_telegram_${chat_id}`).emit(`io_alert_telegram_${chat_id}`, { ...io_message, unique_chat_id_count: 1 });
	}

	// ── Розсилка через notify() по отримувачах токена ──
	try {
		const [[tok]] = await connection_pool.query(`SELECT id, chat_id, topic, topic_id, notify_active FROM ${prefix}telegram_tokens WHERE id = ? LIMIT 1`, [idToken]);

		if (tok && Number(tok.notify_active) === 1) {
			const displayName = last_name ? `${first_name} ${last_name}` : first_name;
			const text = messageData && messageData.text ? String(messageData.text).slice(0, 500) : "";
			const dateStr = `${room_date}.${room_month}.${room_year}, ${room_hours}:${room_minutes}:${room_seconds}`;
			const basePayload = {
				title: displayName,
				message: text,
				url: `/contact-center/telegram/${chat_id}/`,
				chat_id,
				message_id,
				channel: "telegram", // ← щоб фронт знав, що це телеграм-картка
				date: dateStr,
			};

			// CRM отримувачі (in-app дзвіночок)
			const [recipients] = await connection_pool.query(`SELECT kind, ref FROM ${prefix}telegram_notify_recipients WHERE id_token = ?`, [tok.id]);

			for (const r of recipients) {
				if (r.kind === "crm_user") {
					// персональний лічильник цього менеджера
					const [[u]] = await connection_pool.query(`SELECT count FROM ${prefix}telegram_unread WHERE chat_id = ? AND manager_id = ?`, [chat_id, Number(r.ref)]);
					await notifications
						.notify({
							type: "telegram.msg",
							audience: { user: Number(r.ref) },
							channels: ["inapp"],
							collapseKey: `telegram:${chat_id}`,
							payload: { ...basePayload, count: (u && u.count) || 1 },
						})
						.catch((e) => logging.error(e));
				} else if (r.kind === "crm_group") {
					// для групи — беремо максимальний непрочитаний по чату як спільний лічильник
					const [[g]] = await connection_pool.query(`SELECT MAX(count) AS count FROM ${prefix}telegram_unread WHERE chat_id = ?`, [chat_id]);
					await notifications
						.notify({
							type: "telegram.msg",
							audience: { group: Number(r.ref) },
							channels: ["inapp"],
							collapseKey: `telegram:${chat_id}`,
							payload: { ...basePayload, count: (g && g.count) || 1 },
						})
						.catch((e) => logging.error(e));
				}
			}

			// Телеграм-чат токена (якщо вказано)
			if (tok.chat_id) {
				await notifications
					.notify({
						type: "telegram.msg",
						audience: { user: 0 }, // технічний; inbox не створюється (немає inapp)
						channels: ["telegram"],
						payload: {
							...basePayload,
							message: `<b>${displayName}</b>\n${text}`,
							tg_chat_id: tok.chat_id,
							topic_id: tok.topic ? tok.topic_id || null : null,
							bot_token: token,
						},
					})
					.catch((e) => logging.error(e));
			}
		}
	} catch (e) {
		logging.error(e);
	}
};

const createBot = (token, idToken, botId) => {
	const bot = new TelegramBot(token, { polling: true });
	bot.gcIdToken = idToken;
	bot.gcBotId = botId;

	bot.on("polling_error", (error) => {
		console.error(`Polling error:`, error.message);
		bot.stopPolling();
		bots = bots.filter((b) => b.token !== token);
	});

	bot.on("message", async (msg) => {
		try {
			if (msg.chat.type !== "private") return;
			// Дата повідомлення
			const room_date_ob = new Date(msg.date * 1000);
			const room_date = ("0" + room_date_ob.getDate()).slice(-2);
			const room_month = ("0" + (room_date_ob.getMonth() + 1)).slice(-2);
			const room_year = room_date_ob.getFullYear();
			const room_hours = ("0" + room_date_ob.getHours()).slice(-2);
			const room_minutes = ("0" + room_date_ob.getMinutes()).slice(-2);
			const room_seconds = ("0" + room_date_ob.getSeconds()).slice(-2);
			const date = `${room_year}-${room_month}-${room_date} ${room_hours}:${room_minutes}:${room_seconds}`;

			const chat_id = encrypt(bot.gcBotId, msg.chat.id.toString());
			const message_id = msg.message_id;
			const first_name = msg.from.first_name;
			const last_name = msg.from.last_name;
			const username = msg.from.username;
			const language_code = msg.from.language_code;
			const is_bot = msg.from.is_bot;
			const type = msg.chat.type;

			// Парсимо тип і дані повідомлення
			const { type: type_message, data: messageData } = await parseIncomingMessage(msg, bot, token, chat_id);

			// Зберігаємо прив'язку chat_id → bot_id (стабільний ID бота від Telegram).
			// id_token лишаємо для сумісності, але резолв іде по bot_id.
			await connection_pool.execute(
				`INSERT INTO ${prefix}telegram_chat_token (chat_id, bot_id, id_token)
                 VALUES (?, ?, ?)
                 ON DUPLICATE KEY UPDATE bot_id = VALUES(bot_id), id_token = VALUES(id_token)`,
				[chat_id, bot.gcBotId, bot.gcIdToken]
			);

			// Розмова: гарантуємо наявність + reopen, якщо була завершена/архівна
			await ensureConversation(chat_id, true);

			// Сповіщення в Telegram про нове повідомлення
			const [[notifySettings]] = await connection_pool.query(`SELECT * FROM ${prefix}telegram_notify_settings WHERE id = 1`);
			if (notifySettings?.active == 1) {
				const notifyBot = new TelegramBot(decryptToken(notifySettings.token), { polling: false });
				const notifyOptions = notifySettings.notify_type == 1 ? { message_thread_id: notifySettings.topic_id, parse_mode: "HTML" } : { parse_mode: "HTML" };
				notifyBot.sendMessage(notifySettings.chat_id, "У вас нове повідомлення.", notifyOptions);
			}

			// Перевіряємо чи чат БУВ в архіві (до видалення)
			const [[archiveRow]] = await connection_pool.query(`SELECT chat_id FROM ${prefix}telegram_archive WHERE chat_id = ?`, [chat_id]);
			const wasArchived = !!archiveRow;

			// Виводимо чат з архіву
			await connection_pool.query(`DELETE FROM ${prefix}telegram_archive WHERE chat_id = ?`, [chat_id]);

			// Привітання
			const [[workingHoursRow]] = await connection_pool.query(`SELECT working_hours FROM ${prefix}telegram_settings_working_hours WHERE id = 1`);

			if (workingHoursRow) {
				const workingHours = typeof workingHoursRow.working_hours === "string" ? JSON.parse(workingHoursRow.working_hours) : workingHoursRow.working_hours;

				const now = new Date();
				const currentDay = (now.getDay() === 0 ? 7 : now.getDay()).toString();
				const currentHour = now.getHours();
				const isWorking = workingHours[currentDay]?.includes(currentHour);
				const userId = msg.chat.id.toString();
				const langId = language_code === "uk" ? 2 : language_code === "ru" ? 3 : 1;

				const [[chatToken]] = await connection_pool.query(`SELECT greeted FROM ${prefix}telegram_chat_token WHERE chat_id = ?`, [chat_id]);
				const greeted = chatToken?.greeted ?? 0;

				let greetingType = null;

				if (!isWorking) {
					if (greeted !== 1) {
						greetingType = 1;
					}
				} else {
					if (wasArchived || greeted === 0 || greeted === 1) {
						greetingType = 2;
					}
				}

				if (greetingType) {
					const [[greeting]] = await connection_pool.query(`SELECT * FROM ${prefix}telegram_greeting WHERE id_lang = ? AND type = ?`, [langId, greetingType]);
					if (greeting) {
						bot.sendMessage(userId, `<b>${greeting.title}</b>\n${greeting.text}`, { parse_mode: "HTML" });

						await connection_pool.query(`UPDATE ${prefix}telegram_chat_token SET greeted = ? WHERE chat_id = ?`, [greetingType, chat_id]);
					}
				}
			}

			// Зберігаємо повідомлення в БД

			// Зберігаємо повідомлення в БД
			await connection_pool.query(
				`INSERT INTO ${prefix}telegram_message
                 (message_id, chat_id, first_name, last_name, username, language_code, is_bot, type, date, message, type_message)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				[message_id, chat_id, first_name, last_name, username, language_code, is_bot, type, date, JSON.stringify(messageData), type_message]
			);

			const formattedDate = formatTimePassed(date);

			// Оновлюємо лічильники і емітимо socket події
			await updateUnreadAndEmit({
				chat_id,
				first_name,
				last_name,
				message_id,
				messageData,
				type_message,
				formattedDate,
				room_date,
				room_month,
				room_year,
				room_hours,
				room_minutes,
				room_seconds,
				archive: !!archiveRow,
				token,
				idToken: bot.gcIdToken,
			});
		} catch (err) {
			logging.error(err);
			console.error("Error processing message:", err);
		}
	});

	return bot;
};

const updateBots = async () => {
	try {
		const active = await getTokensFromDB(); // [{id, token}]
		const activeTokens = active.map((a) => a.token);

		// Зупиняємо ботів, чиїх токенів більше немає серед активних
		bots = bots.filter((bot) => {
			if (!activeTokens.includes(bot.token)) {
				bot.stopPolling();
				return false;
			}
			return true;
		});

		// Піднімаємо нові
		const toAdd = active.filter((a) => !currentTokens.includes(a.token));
		const newBots = toAdd.map((a) => createBot(a.token, a.id, a.botId));
		bots = [...bots, ...newBots];
		currentTokens = activeTokens;
	} catch (error) {
		console.error("Error updating bots:", error);
	}
};

(async () => {
	await updateBots();
})();

// ================================================================
// ROUTES — GET
// ================================================================

router.get("/contact-center/telegram/:id/", authorizationControllers.isAuthenticated, async (req, res) => {
	const chat_id = req.params.id;

	try {
		const [results1] = await connection_pool.query(
			`SELECT first_name, last_name, username, language_code, is_bot, type
             FROM ${prefix}telegram_message WHERE chat_id = ? LIMIT 1`,
			[chat_id]
		);

		if (!results1.length) {
			return res.redirect("/404");
		}

		const [[conv]] = await connection_pool.query(`SELECT id_manager FROM ${prefix}telegram_conversations WHERE chat_id = ? LIMIT 1`, [chat_id]);

		let data_manager = 0;
		if (conv && conv.id_manager != null) {
			data_manager = Number(conv.id_manager) === Number(req.user.id) ? 1 : 2;
		}

		// Відкрили переписку → нотифікації цього чату прочитані для цього менеджера
		try {
			await connection_pool.query(
				`INSERT IGNORE INTO ${prefix}notification_reads (notification_id, manager_id)
                 SELECT n.id, ? FROM ${prefix}notifications AS n
                 WHERE n.type = 2 AND JSON_UNQUOTE(JSON_EXTRACT(n.data, '$.chat_id')) = ?`,
				[req.user.id, chat_id]
			);
			await connection_pool.query(`DELETE FROM ${prefix}telegram_unread WHERE chat_id = ? AND manager_id = ?`, [chat_id, req.user.id]);

			// Архівуємо in-app сповіщення цього чату для менеджера (нова система notify)
			await connection_pool.query(
				`UPDATE ${prefix}notif_inbox
            SET archived_at = NOW(3)
          WHERE user_id = ? AND collapse_key = ?`,
				[req.user.id, `telegram:${chat_id}`]
			);
		} catch (e) {
			logging.error(e);
			console.error("notif read (telegram):", e.message);
		}

		const botStatus = await getChatBotStatus(chat_id);

		res.render("pages/contact-center/contact-center/telegram/index", {
			i18n: res,
			user: req.user,
			data_telegram_chat_id: chat_id,
			data_telegram: results1,
			data_manager,
			bot_available: botStatus.available ? 1 : 0,
			bot_status_reason: botStatus.reason || "",
			header: { navbar: "" },
		});
	} catch (error) {
		logging.error(error);
		res.status(500).send("Internal Server Error");
	}
});

router.get("/contact-center/telegram/settings/:id([0-9]+)", authorizationControllers.isAuthenticated, async (req, res) => {
	try {
		const [rows] = await connection_pool.query("SELECT * FROM " + configDatabase.prefix + "telegram_tokens WHERE id = ?", [req.params.id]);

		if (!rows.length) return res.status(404).send("Not Found");

		res.render("pages/contact-center/contact-center/telegram/edit", {
			i18n: res,
			user: req.user,
			ns: rows[0],
			header: { navbar: "contact-center" },
		});
	} catch (error) {
		console.error("Error rendering contact center settings:", error);
		res.status(500).send("Internal Server Error");
	}
});

// ================================================================
// ROUTES — POST
// ================================================================

// Отримати історію повідомлень чату
router.post("/contact-center/telegram/", async (req, res) => {
	const { chat_id } = req.body;

	try {
		const [clientMessages] = await connection_pool.query(`SELECT * FROM ${prefix}telegram_message WHERE chat_id = ? ORDER BY message_id ASC`, [chat_id]);

		const [managerMessages] = await connection_pool.query(`SELECT * FROM ${prefix}telegram_message_manager WHERE chat_id = ? ORDER BY id ASC`, [chat_id]);

		const merged = [
			...clientMessages.map((row) => ({
				chat_id: row.chat_id,
				message_id: row.message_id,
				id_manager: null,
				date: new Date(row.date),
				formattedDate: formatDate(row.date),
				message: row.message.text,
				caption: row.message.caption,
				type_message: row.type_message,
			})),
			...managerMessages.map((row) => ({
				chat_id: row.chat_id,
				message_id: row.id,
				id_manager: row.id_manager,
				date: new Date(row.date),
				formattedDate: formatDate(row.date),
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

// Відправити текстове повідомлення менеджером
router.post("/contact-center/telegram/:chat_id/", authorizationControllers.isAuthenticated, async (req, res) => {
	const encrypted_chat_id = req.params.chat_id;
	const { message } = req.body;

	const now = new Date();
	const pad = (n) => String(n).padStart(2, "0");
	const dateStr = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
	const displayDate = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())} ${pad(now.getDate())}.${pad(now.getMonth() + 1)}.${now.getFullYear()}`;

	try {
		await connection_pool.query(
			`INSERT INTO ${prefix}telegram_message_manager (id_manager, chat_id, date, message, type_message)
             VALUES (?, ?, ?, ?, ?)`,
			[req.user.id, encrypted_chat_id, dateStr, message, "text"]
		);

		let token;
		try {
			token = await getBotTokenByChatId(encrypted_chat_id);
		} catch (e) {
			if (String(e.message).startsWith("BOT_UNAVAILABLE")) {
				return res.status(409).json({ error: "BOT_UNAVAILABLE", message: "Бот цього чату вимкнено або видалено. Повідомлення не надіслано." });
			}
			throw e;
		}
		const bot = new TelegramBot(token, { polling: false });
		const { tgChatId: real_chat_id } = decrypt(encrypted_chat_id);

		await bot.sendMessage(real_chat_id, message, { parse_mode: "HTML" });

		res.json({ message, date: displayDate });
	} catch (err) {
		console.error("Error sending message:", err);
		logging.error(err);
		res.status(500).json({ error: "Failed to send message" });
	}
});

// Відправити файл менеджером
router.post("/contact-center/telegram/:id/add-file/", authorizationControllers.isAuthenticated, async (req, res) => {
	const encrypted_chat_id = req.params.id;
	const { tgChatId: real_chat_id } = decrypt(encrypted_chat_id);

	let token;
	try {
		token = await getBotTokenByChatId(encrypted_chat_id);
	} catch (err) {
		return res.status(404).json({ error: "Token not found" });
	}

	const bot = new TelegramBot(token, { polling: false });
	const upload = multer({ storage: multer.memoryStorage() }).single("file");

	upload(req, res, async (err) => {
		if (err) return res.status(500).send("Помилка завантаження файлу.");
		if (!req.file) return res.status(400).send("Файл не був завантажений.");

		const file = req.file;
		const type_message = file.mimetype.startsWith("image/") ? "photo" : "file";
		const now = new Date();
		const pad = (n) => String(n).padStart(2, "0");
		const dateStr = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
		const displayDate = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())} ${pad(now.getDate())}.${pad(now.getMonth() + 1)}.${now.getFullYear()}`;

		try {
			const [result] = await connection_pool.query(
				`INSERT INTO ${prefix}telegram_message_manager (id_manager, chat_id, date, message, type_message)
                 VALUES (?, ?, ?, ?, ?)`,
				[req.user.id, encrypted_chat_id, dateStr, file.originalname, type_message]
			);

			const savePath = path.join("assets", "contact-center", "telegram", encrypted_chat_id, "manager", result.insertId.toString());
			fs.mkdirSync(savePath, { recursive: true });
			const filePath = path.join(savePath, file.originalname);
			fs.writeFileSync(filePath, file.buffer);

			if (type_message === "photo") {
				await bot.sendPhoto(real_chat_id, filePath);
			} else {
				await bot.sendDocument(real_chat_id, filePath);
			}

			io.to(`io_alert_telegram_${encrypted_chat_id}`).emit(`io_alert_telegram_${encrypted_chat_id}`, {
				chat_id: encrypted_chat_id,
				id_manager: req.user.id,
				message_id: result.insertId,
				message: file.originalname,
				type_message,
				date: displayDate,
			});

			res.json({ success: true });
		} catch (error) {
			console.error("Error sending file:", error);
			logging.error(error);
			res.status(500).send("Помилка відправлення файлу.");
		}
	});
});

// Запит номера телефону
router.post("/contact-center/telegram/:id/requestPhoneNumber/", authorizationControllers.isAuthenticated, async (req, res) => {
	const encrypted_chat_id = req.params.id;
	const { tgChatId: real_chat_id } = decrypt(encrypted_chat_id);
	const now = new Date();
	const pad = (n) => String(n).padStart(2, "0");
	const dateStr = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
	const displayDate = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())} ${pad(now.getDate())}.${pad(now.getMonth() + 1)}.${now.getFullYear()}`;

	try {
		const token = await getBotTokenByChatId(encrypted_chat_id);
		const bot = new TelegramBot(token, { polling: false });

		await connection_pool.query(
			`INSERT INTO ${prefix}telegram_message_manager (id_manager, chat_id, date, message, type_message)
             VALUES (?, ?, ?, ?, ?)`,
			[req.user.id, encrypted_chat_id, dateStr, "📱 Відправити номер телефону", "text"]
		);

		await bot.sendMessage(real_chat_id, "Будь ласка, поділіться своїм номером телефону:", {
			reply_markup: {
				keyboard: [[{ text: "📱 Відправити номер телефону", request_contact: true }]],
				resize_keyboard: true,
				one_time_keyboard: true,
			},
		});

		io.to(`io_alert_telegram_${encrypted_chat_id}`).emit(`io_alert_telegram_${encrypted_chat_id}`, {
			chat_id: encrypted_chat_id,
			id_manager: req.user.id,
			message: "📱 Відправити номер телефону",
			type_message: "contact",
			date: displayDate,
		});

		res.json({ message: "Будь ласка, поділіться своїм номером телефону:", date: displayDate });
	} catch (err) {
		console.error("Error requestPhoneNumber:", err);
		logging.error(err);
		res.status(500).json({ error: "Server error" });
	}
});

// Запит локації
router.post("/contact-center/telegram/:id/requestLocation/", authorizationControllers.isAuthenticated, async (req, res) => {
	const encrypted_chat_id = req.params.id;

	try {
		const { tgChatId: real_chat_id } = decrypt(encrypted_chat_id);
		const token = await getBotTokenByChatId(encrypted_chat_id);
		const bot = new TelegramBot(token, { polling: false });

		await bot.sendMessage(real_chat_id, "Будь ласка, поділіться своєю локацією:", {
			reply_markup: {
				keyboard: [[{ text: "📍 Відправити локацію", request_location: true }]],
				resize_keyboard: true,
				one_time_keyboard: true,
			},
		});

		res.status(200).json({ success: true });
	} catch (err) {
		console.error("Error requestLocation:", err);
		logging.error(err);
		res.status(500).send("Помилка відправлення в Telegram.");
	}
});

// Архівувати чат
router.post("/api/contact-center/telegram/archive/", authorizationControllers.isAuthenticated, async (req, res) => {
	const conn = await connection_pool.getConnection();
	try {
		const { id_chat } = req.body;

		if (!id_chat || !/^[a-f0-9]{32}$/i.test(id_chat)) {
			return res.status(400).json({ error: "Невірний формат id_chat" });
		}

		await conn.beginTransaction();

		await conn.query(
			`INSERT INTO ${prefix}telegram_conversations (chat_id, status, archived_at, date_add)
       VALUES (?, 'archived', NOW(), NOW())
       ON DUPLICATE KEY UPDATE status = 'archived', archived_at = NOW(), id_manager = NULL, date_edit = NOW()`,
			[id_chat]
		);

		await conn.query(`UPDATE ${prefix}telegram_chat_token SET greeted = 0 WHERE chat_id = ?`, [id_chat]);

		await conn.commit();

		io.to("io_alert_contact_center").emit("io_chat_archived", { chat_id: id_chat });

		res.status(200).json({ success: true });
	} catch (error) {
		await conn.rollback();
		logging.error(error);
		res.status(500).json({ error: "Помилка сервера" });
	} finally {
		conn.release();
	}
});

// Видалити чат
router.post("/api/contact-center/telegram/delete/", authorizationControllers.isAuthenticated, async (req, res) => {
	const conn = await connection_pool.getConnection();
	try {
		const { id_chat } = req.body;

		if (!id_chat || !/^[a-f0-9]{32}$/i.test(id_chat)) {
			return res.status(400).json({ error: "Невірний формат id_chat" });
		}

		await conn.beginTransaction();

		await Promise.all(["telegram_message", "telegram_message_manager", "telegram_archive", "telegram_manager", "telegram_unread", "telegram_chat_token"].map((table) => conn.query(`DELETE FROM ${prefix}${table} WHERE chat_id = ?`, [id_chat])));

		// Чистимо нотифікації цього чату + персональні позначки прочитання
		await conn.query(
			`DELETE r FROM ${prefix}notification_reads AS r
             INNER JOIN ${prefix}notifications AS n ON n.id = r.notification_id
             WHERE n.type = 2 AND JSON_UNQUOTE(JSON_EXTRACT(n.data, '$.chat_id')) = ?`,
			[id_chat]
		);
		await conn.query(
			`DELETE FROM ${prefix}notifications
             WHERE type = 2 AND JSON_UNQUOTE(JSON_EXTRACT(data, '$.chat_id')) = ?`,
			[id_chat]
		);

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

// Список токенів
router.post("/api/contact-center/telegram/token-list/", authorizationControllers.isAuthenticated, async (req, res) => {
	try {
		const [rows] = await connection_pool.query(`SELECT id, name, description, active, date_add, date_edit FROM ${prefix}telegram_tokens`);

		const formatDt = (val) => {
			if (!val) return val;
			const d = new Date(val);
			const pad = (n) => String(n).padStart(2, "0");
			return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()}, ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
		};

		res.status(200).json(
			rows.map((row) => ({
				...row,
				date_add: formatDt(row.date_add),
				date_edit: formatDt(row.date_edit),
			}))
		);
	} catch (error) {
		logging.error(error);
		res.status(500).json({ success: false, error: "Internal server error" });
	}
});

// Призначити менеджера на чат
router.post("/api/contact-center/telegram/manager/assign/", authorizationControllers.isAuthenticated, async (req, res) => {
	const { chat_id } = req.body;
	const id_manager = req.user.id;

	if (!chat_id) return res.status(400).json({ message: "chat_id обов'язковий." });

	const conn = await connection_pool.getConnection();
	try {
		await conn.query(
			`INSERT INTO ${prefix}telegram_conversations (chat_id, status, date_add)
       VALUES (?, 'open', NOW()) ON DUPLICATE KEY UPDATE id = id`,
			[chat_id]
		);

		const [[conv]] = await conn.query(`SELECT id_manager FROM ${prefix}telegram_conversations WHERE chat_id = ? LIMIT 1`, [chat_id]);
		if (conv && conv.id_manager != null) {
			return res.status(409).json({ message: "Цей чат вже має менеджера." });
		}

		await conn.beginTransaction();

		// Взяти в роботу: assignee + повернути в open (якщо був resolved/archived)
		await conn.query(
			`UPDATE ${prefix}telegram_conversations
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

// Список менеджерів для делегування
router.post("/api/contact-center/managers/list/", authorizationControllers.isAuthenticated, async (req, res) => {
	try {
		const [rows] = await connection_pool.query(
			`SELECT id, CONCAT(first_name, ' ', last_name) AS name
             FROM ${prefix}users
             WHERE id != ? AND active = 1
             ORDER BY first_name ASC`,
			[req.user.id]
		);

		if (!rows.length) return res.status(404).json({ message: "Менеджерів не знайдено." });

		res.status(200).json(rows);
	} catch (error) {
		logging.error(error);
		res.status(500).json({ message: "Помилка сервера." });
	}
});

// Делегувати чат
router.post("/api/contact-center/telegram/manager/delegate/", authorizationControllers.isAuthenticated, async (req, res) => {
	const { chat_id, id_manager } = req.body;

	if (!chat_id || !id_manager) {
		return res.status(400).json({ message: "chat_id та id_manager обов'язкові." });
	}

	try {
		const [[existing]] = await connection_pool.query(`SELECT id_manager FROM ${prefix}telegram_conversations WHERE chat_id = ? LIMIT 1`, [chat_id]);

		if (!existing) {
			return res.status(404).json({ message: "Запис для цього чату не знайдено." });
		}

		await connection_pool.query(`UPDATE ${prefix}telegram_conversations SET id_manager = ?, status = 'open', date_edit = NOW() WHERE chat_id = ?`, [id_manager, chat_id]);

		const [[chatInfo]] = await connection_pool.query(
			`SELECT first_name, last_name FROM ${prefix}telegram_message
             WHERE chat_id = ? ORDER BY id DESC LIMIT 1`,
			[chat_id]
		);

		// Персональний лічильник для нового менеджера
		const [[unreadRow]] = await connection_pool
			.query(
				`SELECT COALESCE(count, 0) AS count FROM ${prefix}telegram_unread
             WHERE chat_id = ? AND manager_id = ?`,
				[chat_id, id_manager]
			)
			.catch(() => [[{ count: 0 }]]);

		if (chatInfo) {
			io.to(`io_manager_${id_manager}`).emit("io_chat_delegated", {
				chat_id,
				first_name: chatInfo.first_name,
				last_name: chatInfo.last_name,
				count: unreadRow?.count ?? 0,
				status: 1,
			});
		}

		io.to(`io_manager_${req.user.id}`).emit("io_chat_removed", { chat_id });

		res.status(200).json({ message: "Менеджера успішно змінено." });
	} catch (error) {
		logging.error(error);
		res.status(500).json({ message: "Помилка сервера." });
	}
});

// Завершити діалог (resolved)
router.post("/api/contact-center/telegram/resolve/", authorizationControllers.isAuthenticated, async (req, res) => {
	const { id_chat } = req.body;
	if (!id_chat || !/^[a-f0-9]{32}$/i.test(id_chat)) {
		return res.status(400).json({ error: "Невірний формат id_chat" });
	}
	try {
		await connection_pool.query(
			`INSERT INTO ${prefix}telegram_conversations (chat_id, status, resolved_at, date_add)
       VALUES (?, 'resolved', NOW(), NOW())
       ON DUPLICATE KEY UPDATE status = 'resolved', resolved_at = NOW(), date_edit = NOW()`,
			[id_chat]
		);
		io.to("io_alert_contact_center").emit("io_chat_resolved", { chat_id: id_chat });
		return res.status(200).json({ success: true });
	} catch (error) {
		logging.error(error);
		return res.status(500).json({ error: "Помилка сервера" });
	}
});

// Медіатека чату
router.get("/api/contact-center/telegram/:chat_id/media/", authorizationControllers.isAuthenticated, async (req, res) => {
	const { chat_id } = req.params;

	if (!/^[a-f0-9]{32}$/i.test(chat_id)) {
		return res.status(400).json({ error: "Невірний формат chat_id" });
	}

	try {
		// Повідомлення клієнта
		const [clientMessages] = await connection_pool.query(
			`SELECT message_id AS id, message, type_message, date, 'client' AS sender
             FROM ${prefix}telegram_message
             WHERE chat_id = ? AND type_message IN ('photo','video','document','audio','sticker','animation','text')
             ORDER BY date DESC`,
			[chat_id]
		);

		// Повідомлення менеджера
		const [managerMessages] = await connection_pool.query(
			`SELECT id, message, type_message, date, 'manager' AS sender
             FROM ${prefix}telegram_message_manager
             WHERE chat_id = ? AND type_message IN ('photo','video','file','audio','text')
             ORDER BY date DESC`,
			[chat_id]
		);

		// URL regex для витягування посилань
		const URL_REGEX = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;

		const result = {
			photos: [],
			videos: [],
			files: [],
			audio: [],
			voice: [],
			gifs: [],
			links: [],
		};

		const allMessages = [...clientMessages.map((r) => ({ ...r, message: typeof r.message === "string" ? JSON.parse(r.message) : r.message })), ...managerMessages.map((r) => ({ ...r, message: { text: r.message } }))].sort((a, b) => new Date(b.date) - new Date(a.date));

		for (const msg of allMessages) {
			const { id, message, type_message, date, sender } = msg;
			const formattedDate = formatDate(date);

			// Базовий шлях до файлу
			const basePath = sender === "client" ? `/assets/contact-center/telegram/${chat_id}/client/${id}/` : `/assets/contact-center/telegram/${chat_id}/manager/${id}/`;

			switch (type_message) {
				case "photo":
					result.photos.push({
						type: "photo",
						url: basePath + message.text,
						caption: message.caption || null,
						date: formattedDate,
						sender,
					});
					break;

				case "video":
					result.videos.push({
						type: "video",
						url: basePath + message.text,
						date: formattedDate,
						sender,
					});
					break;

				case "animation":
					result.gifs.push({
						url: basePath + (message.animation?.file_id || message.text || ""),
						date: formattedDate,
						sender,
					});
					break;

				case "sticker":
					// Стікери не виводимо окремо — пропускаємо
					break;

				case "document":
				case "file": {
					const fileName = message.text || "";
					const ext = path.extname(fileName).toLowerCase().replace(".", "");
					result.files.push({
						url: basePath + fileName,
						name: fileName,
						size: message.size || null,
						ext: ext || "file",
						date: formattedDate,
						sender,
					});
					break;
				}

				case "audio":
					result.audio.push({
						url: basePath + message.text,
						name: message.text || "audio",
						date: formattedDate,
						sender,
					});
					break;

				case "voice":
					result.voice.push({
						url: basePath + (message.voice?.file_id || message.text || ""),
						date: formattedDate,
						sender,
					});
					break;

				case "text": {
					const urls = (message.text || "").match(URL_REGEX);
					if (urls) {
						urls.forEach((url) =>
							result.links.push({
								url,
								text: message.text,
								date: formattedDate,
								sender,
							})
						);
					}
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

router.post("/api/contact-center/telegram/settings/token/validate/", authorizationControllers.isAuthenticated, async (req, res) => {
	try {
		const token = String((req.body || {}).token || "").trim();
		if (!token) return res.status(422).json({ status: "error", message: "Вкажіть токен." });

		const tgRes = await fetch("https://api.telegram.org/bot" + token + "/getMe");
		const tg = await tgRes.json().catch(() => ({}));

		if (!tg.ok) {
			return res.status(422).json({ status: "error", message: "Токен недійсний." });
		}

		return res.json({
			status: "success",
			bot: { id: tg.result.id, username: tg.result.username, first_name: tg.result.first_name },
		});
	} catch (error) {
		console.error("Token validate error:", error);
		return res.status(500).json({ status: "error", message: "Помилка сервера." });
	}
});

// Збереження отримувачів токена (повна заміна набору)
router.post("/api/contact-center/telegram/settings/recipients/save/", authorizationControllers.isAuthenticated, async (req, res) => {
	const conn = await connection_pool.getConnection();
	try {
		const id_token = parseInt(req.body.id, 10);
		const recipients = Array.isArray(req.body.recipients) ? req.body.recipients : [];
		if (!id_token) return res.status(422).json({ status: "error", message: "id обов'язковий" });

		const allowed = new Set(["crm_user", "crm_group", "tg_chat"]);
		const clean = recipients.filter((r) => r && allowed.has(r.kind) && String(r.ref || "").trim()).map((r) => [id_token, r.kind, String(r.ref).trim().slice(0, 64), r.kind === "tg_chat" && String(r.topic_id || "").trim() ? String(r.topic_id).trim().slice(0, 64) : null]);

		await conn.beginTransaction();
		await conn.query(`DELETE FROM ${prefix}telegram_notify_recipients WHERE id_token = ?`, [id_token]);
		if (clean.length) {
			await conn.query(`INSERT INTO ${prefix}telegram_notify_recipients (id_token, kind, ref, topic_id) VALUES ?`, [clean]);
		}
		await conn.commit();
		return res.json({ status: "success" });
	} catch (error) {
		await conn.rollback();
		logging.error(error);
		return res.status(500).json({ status: "error" });
	} finally {
		conn.release();
	}
});

router.post("/api/contact-center/telegram/settings/save/", authorizationControllers.isAuthenticated, async (req, res) => {
	const conn = await connection_pool.getConnection();
	try {
		const b = req.body || {};
		const id = parseInt(b.id, 10);
		if (!id) return res.status(422).json({ status: "error", message: "id обов'язковий" });

		const workingHours = typeof b.working_hours === "string" ? b.working_hours : JSON.stringify(b.working_hours || {});

		await conn.beginTransaction();

		// Токен НЕ редагується через цю форму (незмінний після створення).
		const tokenSql = "";
		const tokenParam = [];

		// 1) Основні поля токена
		await conn.query(
			`UPDATE ${prefix}telegram_tokens
          SET name = ?, description = ?, ${tokenSql} chat_id = ?,
              topic = ?, topic_id = ?, active = ?, notify_active = ?, note = ?,
              color_text = ?, color_background = ?, icon = ?,
              working_hours = CAST(? AS JSON), date_edit = NOW()
        WHERE id = ?`,
			[b.name || "", b.description || "", ...tokenParam, b.chat_id || "", b.topic ? 1 : 0, b.topic_id || "", b.active ? 1 : 0, b.notify_active ? 1 : 0, b.note || "", b.color_text || "", b.color_background || "", b.icon || "", workingHours, id]
		);

		// 2) Отримувачі (повна заміна набору)
		const allowed = new Set(["crm_user", "crm_group"]);
		const recipients = Array.isArray(b.recipients) ? b.recipients : [];
		const clean = recipients.filter((r) => r && allowed.has(r.kind) && String(r.ref || "").trim()).map((r) => [id, r.kind, String(r.ref).trim().slice(0, 64), null]);

		await conn.query(`DELETE FROM ${prefix}telegram_notify_recipients WHERE id_token = ?`, [id]);
		if (clean.length) {
			await conn.query(`INSERT INTO ${prefix}telegram_notify_recipients (id_token, kind, ref, topic_id) VALUES ?`, [clean]);
		}

		await conn.commit();
		return res.json({ status: "success" });
	} catch (error) {
		await conn.rollback();
		logging.error(error);
		return res.status(500).json({ status: "error", message: error.message });
	} finally {
		conn.release();
	}
});

router.post("/api/contact-center/telegram/settings/recipients/list/", authorizationControllers.isAuthenticated, async (req, res) => {
	try {
		const id_token = parseInt(req.body.id, 10);
		if (!id_token) return res.status(422).json({ status: "error", message: "id обов'язковий" });
		const id_lang = req.user.id_lang || 1;

		const [rows] = await connection_pool.query(
			`SELECT r.kind, r.ref,
              CASE
                WHEN r.kind = 'crm_user'  THEN TRIM(CONCAT(COALESCE(u.last_name,''),' ',COALESCE(u.first_name,'')))
                WHEN r.kind = 'crm_group' THEN gl.name
              END AS name
         FROM ${prefix}telegram_notify_recipients r
         LEFT JOIN ${prefix}users u
                ON r.kind = 'crm_user' AND u.id = r.ref
         LEFT JOIN ${prefix}users_groups_lang gl
                ON r.kind = 'crm_group' AND gl.id_group = r.ref AND gl.id_lang = ?
        WHERE r.id_token = ?
        ORDER BY r.id ASC`,
			[id_lang, id_token]
		);

		return res.json({ status: "success", data: rows });
	} catch (error) {
		logging.error(error);
		return res.status(500).json({ status: "error" });
	}
});

// ================================================================
// Деактивація / активація токена-бота (active 0/1) + керування polling
// ================================================================
router.post("/api/contact-center/telegram/settings/token/toggle/", authorizationControllers.isAuthenticated, async (req, res) => {
	const id = parseInt(req.body.id, 10);
	const active = req.body.active ? 1 : 0;
	if (!id) return res.status(422).json({ status: "error", message: "id обов'язковий" });

	try {
		const [[tok]] = await connection_pool.query(`SELECT id FROM ${prefix}telegram_tokens WHERE id = ? LIMIT 1`, [id]);
		if (!tok) return res.status(404).json({ status: "error", message: "Токен не знайдено." });

		await connection_pool.query(`UPDATE ${prefix}telegram_tokens SET active = ?, date_edit = NOW() WHERE id = ?`, [active, id]);

		// Синхронізуємо ботів у пам'яті за id_token (bots[].token — розшифрований)
		try {
			if (active === 0) {
				const target = bots.find((b) => b.gcIdToken === id);
				if (target) {
					if (typeof target.stopPolling === "function") target.stopPolling();
					currentTokens = currentTokens.filter((t) => t !== target.token);
					bots = bots.filter((b) => b.gcIdToken !== id);
				}
			} else {
				await updateBots();
			}
		} catch (e) {
			logging.error(e);
		}

		return res.json({ status: "success", active, message: active ? "Бот активовано." : "Бот деактивовано." });
	} catch (error) {
		logging.error(error);
		return res.status(500).json({ status: "error", message: "Помилка сервера." });
	}
});

// ================================================================
// Видалення токена-бота (фізичне) + зупинка бота + отримувачі.
// Чати НЕ чіпаємо: лишаються, але стають неробочими (BOT_UNAVAILABLE).
// ================================================================
router.post("/api/contact-center/telegram/settings/token/delete/", authorizationControllers.isAuthenticated, async (req, res) => {
	const id = parseInt(req.body.id, 10);
	if (!id) return res.status(422).json({ status: "error", message: "id обов'язковий" });

	const conn = await connection_pool.getConnection();
	try {
		const [[tok]] = await conn.query(`SELECT id FROM ${prefix}telegram_tokens WHERE id = ? LIMIT 1`, [id]);
		if (!tok) {
			conn.release();
			return res.status(404).json({ status: "error", message: "Токен не знайдено." });
		}

		await conn.beginTransaction();
		await conn.query(`DELETE FROM ${prefix}telegram_notify_recipients WHERE id_token = ?`, [id]);
		await conn.query(`DELETE FROM ${prefix}telegram_tokens WHERE id = ?`, [id]);
		await conn.commit();

		// Зупиняємо бота цього токена в пам'яті
		try {
			const target = bots.find((b) => b.gcIdToken === id);
			if (target) {
				if (typeof target.stopPolling === "function") target.stopPolling();
				currentTokens = currentTokens.filter((t) => t !== target.token);
				bots = bots.filter((b) => b.gcIdToken !== id);
			}
		} catch (e) {
			logging.error(e);
		}

		return res.json({ status: "success", message: "Токен видалено." });
	} catch (error) {
		await conn.rollback();
		logging.error(error);
		return res.status(500).json({ status: "error", message: "Помилка сервера." });
	} finally {
		conn.release();
	}
});

// ================================================================
// Створення нового токена-бота. Токен валідується і шифрується.
// ================================================================
router.post("/api/contact-center/telegram/settings/token/create/", authorizationControllers.isAuthenticated, async (req, res) => {
	try {
		const b = req.body || {};
		const rawToken = String(b.token || "").trim();
		const name = String(b.name || "").trim();

		if (!rawToken) return res.status(422).json({ status: "error", message: "Вкажіть токен." });
		if (!name) return res.status(422).json({ status: "error", message: "Вкажіть назву." });

		// Перевірка токена в Telegram
		const tgRes = await fetch("https://api.telegram.org/bot" + rawToken + "/getMe");
		const tg = await tgRes.json().catch(() => ({}));
		if (!tg.ok) return res.status(422).json({ status: "error", message: "Токен недійсний." });

		// Захист від дублю того самого бота (порівнюємо по розшифрованому токену)
		const [existing] = await connection_pool.query(`SELECT id, token FROM ${prefix}telegram_tokens`);
		for (const row of existing) {
			try {
				if (decryptToken(row.token) === rawToken) {
					return res.status(409).json({ status: "error", message: "Цей бот уже доданий." });
				}
			} catch (e) {
				/* пропускаємо биті записи */
			}
		}

		const enc = encryptToken(rawToken);
		const weekHours = [9, 10, 11, 12, 13, 14, 15, 16, 17, 18];
		const defaultHours = JSON.stringify({ 1: weekHours, 2: weekHours, 3: weekHours, 4: weekHours, 5: weekHours });
		const botId = tg.result.id;

		const [ins] = await connection_pool.query(
			`INSERT INTO ${prefix}telegram_tokens
        (bot_id, token, chat_id, topic, topic_id, name, description,
         color_text, color_background, icon, working_hours,
         active, notify_active, note, date_add, date_edit)
       VALUES (?, ?, '', 0, '', ?, ?, '#ffffff', '#3498db', 'fa-brands fa-telegram',
               CAST(? AS JSON), 1, 0, '', NOW(), NOW())`,
			[botId, enc, name, "@" + (tg.result.username || ""), defaultHours]
		);

		// Піднімаємо бота одразу
		await updateBots();

		return res.json({ status: "success", id: ins.insertId, username: tg.result.username });
	} catch (error) {
		logging.error(error);
		return res.status(500).json({ status: "error", message: "Помилка сервера." });
	}
});

module.exports = router;
