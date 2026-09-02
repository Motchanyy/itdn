const express = require("express");
const TelegramBot = require("node-telegram-bot-api");
const router = express.Router();

// Controllers
const authorizationControllers = require("../../controllers/authorization/authorization");
// END Controllers

//Database connection
const connection = require("../../config/database/database");
const connection_pool = require("../../config/database/connection_pool");
//END Database connection

// Configuration
const config = require("../../config/config");
const configDatabase = config.get("configDatabase");
// END Configuration

// Логування
const logging = require("../../logging/logging");
// END Логування

router.get("/contact-center/", authorizationControllers.isAuthenticated, (req, res) => {
	res.render("pages/contact-center/contact-center/index", {
		i18n: res,
		user: req.user,
		header: {
			navbar: "contact-center",
		},
	});
});

router.get("/contact-center/settings/", authorizationControllers.isAuthenticated, (req, res) => {
	res.render("pages/contact-center/contact-center/index", {
		i18n: res,
		user: req.user,
		header: {
			navbar: "contact-center",
		},
	});
});

router.get("/contact-center/telegram/settings/", authorizationControllers.isAuthenticated, async (req, res) => {
	try {
		const notify_settings = await connection_pool.query("SELECT * FROM " + configDatabase.prefix + "telegram_notify_settings WHERE id = 1");
		res.render("pages/contact-center/contact-center/telegram/settings", {
			i18n: res,
			user: req.user,
			data: {
				notify_settings: notify_settings[0],
			},
			header: {
				navbar: "contact-center",
			},
		});
	} catch (error) {
		console.error("Error rendering contact center settings:", error);
		res.status(500).send("Internal Server Error");
	}
});

// POST
const parseCount = (data) => {
	if (!data) return 0;
	try {
		const parsed = typeof data === "string" ? JSON.parse(data) : data;
		return parsed?.count || 0;
	} catch {
		return 0;
	}
};

router.post("/api/contact-center/get-list-chats/", authorizationControllers.isAuthenticated, async (req, res) => {
	const conn = await connection_pool.getConnection();

	try {
		const currentUserId = req.user.id;
		const P = configDatabase.prefix;

		const view = req.body && req.body.view === "mine" ? "mine" : "all";
		const tab = ["open", "resolved", "archived"].includes(req.body && req.body.tab) ? req.body.tab : "open";
		const limit = Math.min(Math.max(parseInt(req.body && req.body.limit, 10) || 30, 1), 100);

		// Мапа статусів на канали
		const tgStatus = tab; // telegram_conversations.status: open/resolved/archived
		const wcStatus = tab === "resolved" ? "closed" : tab; // web_chat: closed = resolved
		const cursorRaw = req.body && req.body.cursor ? String(req.body.cursor) : null;
		const hasCursor = !!cursorRaw;
		const cursorSql = cursorRaw;

		const params = [];

		// --- TELEGRAM гілка ---
		let tgMine = "";
		if (view === "mine") tgMine = "AND conv.id_manager = ?";

		const tgSelect = `
            SELECT
                'telegram' AS channel,
                tm.chat_id COLLATE utf8mb4_unicode_ci AS chat_id,
                '' AS site_id,
                tm.first_name AS first_name,
                tm.last_name AS last_name,
                tm.max_id AS max_id,
                tm.last_at AS last_at,
                COALESCE(ur.count, 0) AS count,
                conv.id_manager AS id_manager,
                '' AS domains,
                '' AS url_token,
                CASE WHEN tkn.id IS NULL THEN 0 ELSE 1 END AS bot_available
            FROM (
                SELECT chat_id,
                       MAX(id) AS max_id,
                       CAST(MAX(date) AS DATETIME(3)) AS last_at,
                       SUBSTRING_INDEX(GROUP_CONCAT(first_name ORDER BY id DESC SEPARATOR 0x1f), 0x1f, 1) AS first_name,
                       SUBSTRING_INDEX(GROUP_CONCAT(last_name  ORDER BY id DESC SEPARATOR 0x1f), 0x1f, 1) AS last_name
                FROM ${P}telegram_message
                GROUP BY chat_id
            ) AS tm
            INNER JOIN ${P}telegram_conversations AS conv ON conv.chat_id = tm.chat_id AND conv.status = ?
            LEFT JOIN ${P}telegram_unread  AS ur  ON ur.chat_id = tm.chat_id AND ur.manager_id = ?
            LEFT JOIN ${P}telegram_chat_token AS ctk ON ctk.chat_id = tm.chat_id
            LEFT JOIN ${P}telegram_tokens AS tkn
                   ON tkn.active = 1
                  AND (
                        (ctk.bot_id IS NOT NULL AND tkn.bot_id = ctk.bot_id)
                     OR (ctk.bot_id IS NULL AND tkn.id = ctk.id_token)
                      )
            WHERE 1=1
              ${tgMine}
        `;
		params.push(tgStatus); // conv.status
		params.push(currentUserId); // ur.manager_id
		if (view === "mine") params.push(currentUserId); // conv.id_manager (через tgMine)

		// --- WEBCHAT гілка ---
		let wcMine = "";
		if (view === "mine") wcMine = "AND c.operator_id = ?";

		const wcSelect = `
              SELECT
                'webchat' AS channel,
                c.room_id AS chat_id,
                c.site_id AS site_id,
                '' AS first_name,
                '' AS last_name,
                0 AS max_id,
                lm.last_at AS last_at,
                0 AS count,
                c.operator_id AS id_manager,
                s.domains AS domains,
                c.url_token AS url_token,
                1 AS bot_available
            FROM ${P}web_chat_conversations AS c
            INNER JOIN (
                SELECT id_chat, site_id, CAST(MAX(date_add) AS DATETIME(3)) AS last_at
                FROM ${P}web_chat_messages
                WHERE deleted_at IS NULL
                GROUP BY id_chat, site_id
            ) AS lm ON lm.id_chat = c.room_id AND lm.site_id = c.site_id
            LEFT JOIN ${P}web_chat_sites AS s ON s.site_id = c.site_id
            WHERE c.status = ?
              ${wcMine}
        `;
		params.push(wcStatus); // c.status
		if (view === "mine") params.push(currentUserId); // c.operator_id

		// --- INSTAGRAM гілка ---
		let igMine = "";
		if (view === "mine") igMine = "AND conv.id_manager = ?";

		const igSelect = `
            SELECT
                'instagram' AS channel,
                im.chat_id AS chat_id,
                '' AS site_id,
                im.first_name AS first_name,
                im.last_name AS last_name,
                im.max_id AS max_id,
                im.last_at AS last_at,
                COALESCE(ur.count, 0) AS count,
                conv.id_manager AS id_manager,
                '' AS domains,
                '' AS url_token,
                CASE WHEN tkn.id IS NULL THEN 0 ELSE 1 END AS bot_available
            FROM (
				SELECT chat_id,
                       MAX(id) AS max_id,
                       CAST(MAX(date) AS DATETIME(3)) AS last_at,
                       MAX(NULLIF(first_name, '')) AS first_name,
                       MAX(NULLIF(last_name, '')) AS last_name
                FROM ${P}instagram_message
                GROUP BY chat_id
            ) AS im
            INNER JOIN ${P}instagram_conversations AS conv ON conv.chat_id = im.chat_id AND conv.status = ?
            LEFT JOIN ${P}instagram_unread AS ur ON ur.chat_id = im.chat_id AND ur.manager_id = ?
            LEFT JOIN ${P}instagram_chat_token AS ctk ON ctk.chat_id = im.chat_id
            LEFT JOIN ${P}instagram_tokens AS tkn ON tkn.active = 1 AND tkn.ig_id = ctk.ig_id
            WHERE 1=1
              ${igMine}
        `;
		params.push(tab); // conv.status (instagram теж open/resolved/archived)
		params.push(currentUserId); // ur.manager_id
		if (view === "mine") params.push(currentUserId); // conv.id_manager

		// --- об'єднання + спільний курсор + єдиний LIMIT ---
		let unionSql = `
            SELECT * FROM (
                ( ${tgSelect} )
                UNION ALL
                ( ${wcSelect} )
                UNION ALL
                ( ${igSelect} )
            ) AS merged
        `;
		const cursorCh = req.body && req.body.cursorCh ? String(req.body.cursorCh) : null;
		const cursorId = req.body && req.body.cursorId ? String(req.body.cursorId) : null;
		if (hasCursor && cursorCh != null && cursorId != null) {
			unionSql += ` WHERE (CAST(merged.last_at AS DATETIME(3)) < CAST(? AS DATETIME(3))
                OR (CAST(merged.last_at AS DATETIME(3)) = CAST(? AS DATETIME(3)) AND merged.channel > ?)
                OR (CAST(merged.last_at AS DATETIME(3)) = CAST(? AS DATETIME(3)) AND merged.channel = ? AND merged.chat_id > ?))`;
			params.push(cursorSql, cursorSql, cursorCh, cursorSql, cursorCh, cursorId);
		}
		unionSql += `
            ORDER BY CAST(merged.last_at AS DATETIME(3)) DESC, merged.channel ASC, merged.chat_id ASC
            LIMIT ${limit}
        `;

		const [rows] = await conn.query(unionSql, params);
		const pageRows = rows;
		const hasMore = rows.length === limit;

		const items = [];
		pageRows.forEach((row) => {
			let status;
			if (row.id_manager === null) status = 0;
			else if (row.id_manager === currentUserId) status = 1;
			else status = 2;

			if (row.channel === "telegram") {
				if (status === 2) return;
				const title = [row.first_name, row.last_name].filter(Boolean).join(" ") || "—";
				items.push({ channel: "telegram", chat_id: row.chat_id, site_id: "", title, count: row.count | 0, status, max_id: row.max_id | 0, last_at: row.last_at, bot_available: Number(row.bot_available) === 1 ? 1 : 0 });
			} else if (row.channel === "instagram") {
				if (status === 2) return;
				const title = [row.first_name, row.last_name].filter(Boolean).join(" ") || "—";
				items.push({ channel: "instagram", chat_id: row.chat_id, site_id: "", title, count: row.count | 0, status, max_id: row.max_id | 0, last_at: row.last_at, bot_available: Number(row.bot_available) === 1 ? 1 : 0 });
			} else {
				if (status === 2 && view === "mine") return;
				const domain = String(row.domains || "").split(/[,\s]+/)[0] || "web";
				const shortId = String(row.chat_id).split("_v_")[1] || row.chat_id;
				const title = domain + " · " + String(shortId).slice(0, 6);
				items.push({ channel: "webchat", chat_id: row.chat_id, site_id: row.site_id || "", url_token: row.url_token || "", title, count: row.count | 0, status, max_id: 0, last_at: row.last_at });
			}
		});

		const last = pageRows[pageRows.length - 1];
		const nextCursor = hasMore && last ? String(last.last_at) : null;
		const nextCursorCh = hasMore && last ? last.channel : null;
		const nextCursorId = hasMore && last ? last.chat_id : null;

		res.status(200).json({ items, nextCursor, nextCursorCh, nextCursorId });
	} catch (error) {
		console.error("Помилка отримання списку чатів:", error);
		logging.error(error);
		res.status(500).json({ error: "server_error" });
	} finally {
		conn.release();
	}
});

router.post("/api/contact-center/telegram/settings/working-hours/select/", async (req, res) => {
	if (!["127.0.0.1", "::1"].includes(req.ip.replace("::ffff:", ""))) {
		return res.status(403).json({ message: "Forbidden: Access denied" });
	}

	connection.query("SELECT working_hours FROM " + configDatabase.prefix + "telegram_settings_working_hours WHERE id = 1", function (error, result) {
		if (error) {
			console.log(error);
			logging.error(error);
		}

		res.send(result[0].working_hours);
	});
});
router.post("/api/contact-center/telegram/settings/working-hours/insert/", async (req, res) => {
	var working_hours = req.body.working_hours;

	console.log(working_hours);

	if (!["127.0.0.1", "::1"].includes(req.ip.replace("::ffff:", ""))) {
		return res.status(403).json({ message: "Forbidden: Access denied" });
	}

	connection.query("UPDATE " + configDatabase.prefix + "telegram_settings_working_hours SET working_hours = ? WHERE id = 1", [working_hours], function (error, result) {
		if (error) {
			console.log(error);
			logging.error(error);
		}

		res.send({ success: "success" });
	});
});
// END POST

// ── Веб-чат: сторінка діалогу (по непрозорому url_token) ──
router.get("/contact-center/webchat/:token/", authorizationControllers.isAuthenticated, async (req, res) => {
	const token = String(req.params.token || "");
	// токен — рівно 32 hex; інші формати одразу відкидаємо
	if (!/^[a-f0-9]{32}$/.test(token)) return res.redirect("/contact-center/");
	try {
		const [rows] = await connection_pool.query(`SELECT site_id, room_id FROM ${configDatabase.prefix}web_chat_conversations WHERE url_token = ? LIMIT 1`, [token]);
		if (!rows.length) return res.redirect("/contact-center/");

		res.render("pages/contact-center/contact-center/webchat/dialog", {
			i18n: res,
			user: req.user,
			data: {
				roomId: rows[0].room_id,
				siteId: rows[0].site_id,
			},
			header: { navbar: "contact-center" },
		});
	} catch (error) {
		logging.error(error);
		res.status(500).send("Internal Server Error");
	}
});

// ── Веб-чат: сторінка налаштувань сайтів ──
router.get("/contact-center/webchat/settings/", authorizationControllers.isAuthenticated, (req, res) => {
	res.render("pages/contact-center/contact-center/webchat/settings", {
		i18n: res,
		user: req.user,
		header: { navbar: "contact-center" },
	});
});

// ── Веб-чат: сторінка редагування сайту ──
router.get("/contact-center/webchat/settings/:siteId/", authorizationControllers.isAuthenticated, async (req, res) => {
	const P = configDatabase.prefix;
	const siteId = req.params.siteId;
	try {
		const [rows] = await connection_pool.query(
			`SELECT site_id, domains, active, product_card_enabled, lead_timeout_sec,
                    offline_lead_enabled, offline_lead_delay_sec, brand_color, config
             FROM ${P}web_chat_sites WHERE site_id = ? LIMIT 1`,
			[siteId]
		);
		if (!rows.length) return res.redirect("/contact-center/webchat/settings/");

		const site = rows[0];
		if (site.config && typeof site.config === "object") site.config = JSON.stringify(site.config);

		res.render("pages/contact-center/contact-center/webchat/settings-edit", {
			i18n: res,
			user: req.user,
			data: { site },
			header: { navbar: "contact-center" },
		});
	} catch (error) {
		console.error("webchat settings edit page:", error.message);
		logging.error(error);
		res.status(500).send("Internal Server Error");
	}
});

// ── Веб-чат: список сайтів для таблиці налаштувань ──
router.post("/api/contact-center/webchat/settings/list/", authorizationControllers.isAuthenticated, async (req, res) => {
	const P = configDatabase.prefix;
	try {
		const [rows] = await connection_pool.query(
			`SELECT site_id, domains, active, product_card_enabled,
                    lead_timeout_sec, offline_lead_enabled, offline_lead_delay_sec, brand_color, config
             FROM ${P}web_chat_sites
             ORDER BY site_id ASC`
		);
		// config → рядок JSON, щоб Tabulator не намагався рендерити обʼєкт
		rows.forEach((r) => {
			if (r.config && typeof r.config === "object") r.config = JSON.stringify(r.config);
		});
		res.send(rows);
	} catch (error) {
		console.error("webchat settings list:", error.message);
		logging.error(error);
		res.status(500).send([]);
	}
});

// ── Веб-чат: додати сайт ──
router.post("/api/contact-center/webchat/settings/insert/", authorizationControllers.isAuthenticated, async (req, res) => {
	const P = configDatabase.prefix;
	const b = req.body || {};

	const siteId = String(b.site_id || "").trim();
	if (!siteId || siteId.length > 190) return res.status(400).json({ error: "Невірний Site ID" });

	const domains = String(b.domains || "")
		.trim()
		.slice(0, 5000);
	const brandColor = /^#[0-9a-fA-F]{6}$/.test(b.brand_color) ? b.brand_color : "#007fff";
	const leadTimeout = Math.max(0, parseInt(b.lead_timeout_sec, 10) || 0);
	const offlineDelay = Math.max(0, parseInt(b.offline_lead_delay_sec, 10) || 0);
	const active = b.active ? 1 : 0;
	const productCard = b.product_card_enabled ? 1 : 0;
	const offlineLead = b.offline_lead_enabled ? 1 : 0;

	// config: приймаємо рядок JSON, валідуємо
	let configStr = null;
	if (b.config != null && String(b.config).trim() !== "") {
		try {
			const parsed = typeof b.config === "string" ? JSON.parse(b.config) : b.config;
			configStr = JSON.stringify(parsed);
		} catch (e) {
			return res.status(400).json({ error: "Невалідний JSON у config" });
		}
	}

	try {
		const [result] = await connection_pool.query(
			`UPDATE ${P}web_chat_sites SET
                domains = ?, active = ?, product_card_enabled = ?, lead_timeout_sec = ?,
                offline_lead_enabled = ?, offline_lead_delay_sec = ?, brand_color = ?,
                config = COALESCE(CAST(? AS JSON), config)
             WHERE site_id = ?`,
			[domains, active, productCard, leadTimeout, offlineLead, offlineDelay, brandColor, configStr, siteId]
		);
		res.status(200).json({ success: true });
	} catch (error) {
		console.error("webchat settings insert:", error.message);
		logging.error(error);
		res.status(500).json({ error: "Помилка сервера" });
	}
});

// ── Веб-чат: оновити сайт ──
router.post("/api/contact-center/webchat/settings/update/", authorizationControllers.isAuthenticated, async (req, res) => {
	const P = configDatabase.prefix;
	const b = req.body || {};

	const siteId = String(b.site_id || "").trim();
	if (!siteId) return res.status(400).json({ error: "Невірний Site ID" });

	const domains = String(b.domains || "")
		.trim()
		.slice(0, 5000);
	const brandColor = /^#[0-9a-fA-F]{6}$/.test(b.brand_color) ? b.brand_color : "#007fff";
	const leadTimeout = Math.max(0, parseInt(b.lead_timeout_sec, 10) || 0);
	const offlineDelay = Math.max(0, parseInt(b.offline_lead_delay_sec, 10) || 0);
	const active = b.active ? 1 : 0;
	const productCard = b.product_card_enabled ? 1 : 0;
	const offlineLead = b.offline_lead_enabled ? 1 : 0;

	// config: приймаємо рядок JSON, валідуємо
	let configStr = null;
	if (b.config != null && String(b.config).trim() !== "") {
		try {
			const parsed = typeof b.config === "string" ? JSON.parse(b.config) : b.config;
			configStr = JSON.stringify(parsed);
		} catch (e) {
			return res.status(400).json({ error: "Невалідний JSON у config" });
		}
	}

	try {
		const [result] = await connection_pool.query(
			`UPDATE ${P}web_chat_sites SET
                domains = ?, active = ?, product_card_enabled = ?, lead_timeout_sec = ?,
                offline_lead_enabled = ?, offline_lead_delay_sec = ?, brand_color = ?,
                config = COALESCE(CAST(? AS JSON), config)
             WHERE site_id = ?`,
			[domains, active, productCard, leadTimeout, offlineLead, offlineDelay, brandColor, configStr, siteId]
		);
		if (result.affectedRows === 0) return res.status(404).json({ error: "Сайт не знайдено" });
		res.status(200).json({ success: true });
	} catch (error) {
		console.error("webchat settings update:", error.message);
		logging.error(error);
		res.status(500).json({ error: "Помилка сервера" });
	}
});

// ── Веб-чат: деактивувати сайт (м'яко) ──
router.post("/api/contact-center/webchat/settings/deactivate/", authorizationControllers.isAuthenticated, async (req, res) => {
	const P = configDatabase.prefix;
	const siteId = String((req.body && req.body.site_id) || "").trim();
	if (!siteId) return res.status(400).json({ error: "site_id обов'язковий" });
	try {
		const [r] = await connection_pool.query(`UPDATE ${P}web_chat_sites SET active = 0 WHERE site_id = ?`, [siteId]);
		if (r.affectedRows === 0) return res.status(404).json({ error: "Сайт не знайдено" });
		res.status(200).json({ success: true });
	} catch (e) {
		console.error("webchat deactivate:", e.message);
		logging.error(e);
		res.status(500).json({ error: "Помилка сервера" });
	}
});

// ── Веб-чат: повне каскадне видалення сайту ──
router.post("/api/contact-center/webchat/settings/delete/", authorizationControllers.isAuthenticated, async (req, res) => {
	const P = configDatabase.prefix;
	const siteId = String((req.body && req.body.site_id) || "").trim();
	const confirm = String((req.body && req.body.confirm) || "").trim();
	if (!siteId) return res.status(400).json({ error: "site_id обов'язковий" });
	if (confirm !== siteId) return res.status(400).json({ error: "Підтвердження не збігається" });

	const conn = await connection_pool.getConnection();
	try {
		await conn.beginTransaction();

		// усі кімнати цього сайту (для чищення нотифікацій по room_id)
		const [rooms] = await conn.query(`SELECT room_id FROM ${P}web_chat_conversations WHERE site_id = ?`, [siteId]);

		// повʼязані таблиці з колонкою site_id
		const tablesBySite = ["web_chat_conversations", "web_chat_messages", "web_chat_leads", "web_chat_visitor_meta", "web_chat_visitor_products", "web_chat_operator_reads", "web_chat_client_reads", "web_chat_sessions"];

		for (const t of tablesBySite) {
			await conn.query(`DELETE FROM ${P}${t} WHERE site_id = ?`, [siteId]).catch(function () {});
		}

		// нотифікації веб-чату цього сайту (type=3) + їх reads
		if (rooms.length) {
			const roomIds = rooms.map(function (r) {
				return r.room_id;
			});
			const ph = roomIds
				.map(function () {
					return "?";
				})
				.join(",");
			await conn
				.query(
					`DELETE r FROM ${P}notification_reads AS r
                 INNER JOIN ${P}notifications AS n ON n.id = r.notification_id
                 WHERE n.type = 3 AND JSON_UNQUOTE(JSON_EXTRACT(n.data,'$.site_id')) = ?`,
					[siteId]
				)
				.catch(function () {});
			await conn
				.query(
					`DELETE FROM ${P}notifications
                 WHERE type = 3 AND JSON_UNQUOTE(JSON_EXTRACT(data,'$.site_id')) = ?`,
					[siteId]
				)
				.catch(function () {});
		}

		// сам сайт
		await conn.query(`DELETE FROM ${P}web_chat_sites WHERE site_id = ?`, [siteId]);

		await conn.commit();
		res.status(200).json({ success: true });
	} catch (e) {
		await conn.rollback();
		console.error("webchat delete:", e.message);
		logging.error(e);
		res.status(500).json({ error: "Помилка сервера при видаленні" });
	} finally {
		conn.release();
	}
});

// ── Веб-чат: активувати сайт ──
router.post("/api/contact-center/webchat/settings/activate/", authorizationControllers.isAuthenticated, async (req, res) => {
	const P = configDatabase.prefix;
	const siteId = String((req.body && req.body.site_id) || "").trim();
	if (!siteId) return res.status(400).json({ error: "site_id обов'язковий" });
	try {
		const [r] = await connection_pool.query(`UPDATE ${P}web_chat_sites SET active = 1 WHERE site_id = ?`, [siteId]);
		if (r.affectedRows === 0) return res.status(404).json({ error: "Сайт не знайдено" });
		res.status(200).json({ success: true });
	} catch (e) {
		console.error("webchat activate:", e.message);
		logging.error(e);
		res.status(500).json({ error: "Помилка сервера" });
	}
});

module.exports = router;
