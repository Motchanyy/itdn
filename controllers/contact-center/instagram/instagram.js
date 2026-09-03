/**
 * =====================================================
 * INSTAGRAM CORE — спільні хелпери
 * Шифрування токенів, деривація chat_id, підпис, резолв акаунта.
 * =====================================================
 */
const crypto = require("crypto");
const connection_pool = require("../../../config/database/connection_pool");
const config = require("../../../config/config");
const configDatabase = config.get("configDatabase");
const prefix = configDatabase.prefix;

const APP_SECRET = process.env.IG_APP_SECRET || "";
const GRAPH = `https://graph.instagram.com/${process.env.IG_GRAPH_VERSION || "v21.0"}`;

// ── Шифрування BOT/USER-ТОКЕНА (AES-256-GCM) — 1:1 з твоїм telegram ──
// Ключ беремо з того самого env, що й telegram (telegramTokenKey), або окремий IG-ключ.
const TOKEN_KEY = Buffer.from(config.get("telegramTokenKey").telegramTokenKey, "hex");

const APP_ID = process.env.IG_APP_ID || "";
const REDIRECT_URI = process.env.IG_REDIRECT_URI || "";

// Скоупи для повідомлень.  ⚠ звірити з актуальною до154кою
const IG_SCOPES = ["instagram_business_basic", "instagram_business_manage_messages"].join(",");

/**
 * URL, куди відправляємо менеджера, щоб підключити акаунт.
 * state — захист від CSRF (звіримо в callback).
 */
const buildAuthUrl = (state) => {
	const p = new URLSearchParams({
		client_id: APP_ID,
		redirect_uri: REDIRECT_URI,
		response_type: "code",
		scope: IG_SCOPES,
		state,
	});
	// ⚠ звірити хост авторизації (instagram.com/oauth/authorize)
	return `https://www.instagram.com/oauth/authorize?${p.toString()}`;
};

/**
 * code → короткоживучий токен (+ user_id).
 */
const exchangeCode = async (code) => {
	const body = new URLSearchParams({
		client_id: APP_ID,
		client_secret: APP_SECRET,
		grant_type: "authorization_code",
		redirect_uri: REDIRECT_URI,
		code,
	});
	// ⚠ звірити: api.instagram.com/oauth/access_token
	const r = await fetch("https://api.instagram.com/oauth/access_token", { method: "POST", body });
	const j = await r.json().catch(() => ({}));
	if (!r.ok || j.error_type || !j.access_token) throw new Error(j.error_message || "OAUTH_EXCHANGE_FAILED");
	return { token: j.access_token, userId: String(j.user_id) };
};

/**
 * короткоживучий → довгоживучий (~60 днів).
 */
const toLongLived = async (shortToken) => {
	const p = new URLSearchParams({ grant_type: "ig_exchange_token", client_secret: APP_SECRET, access_token: shortToken });
	const r = await fetch(`${GRAPH}/access_token?${p.toString()}`);
	const j = await r.json().catch(() => ({}));
	if (!r.ok || !j.access_token) throw new Error("LONG_LIVED_FAILED");
	return { token: j.access_token, expiresIn: Number(j.expires_in) || 60 * 24 * 3600 };
};

/**
 * Продовження довгоживучого токена (раз на 24h–60д, ми робимо ~кожні 50 днів).
 */
const refreshLongLived = async (longToken) => {
	const p = new URLSearchParams({ grant_type: "ig_refresh_token", access_token: longToken });
	const r = await fetch(`${GRAPH}/refresh_access_token?${p.toString()}`);
	const j = await r.json().catch(() => ({}));
	if (!r.ok || !j.access_token) throw new Error("REFRESH_FAILED");
	return { token: j.access_token, expiresIn: Number(j.expires_in) || 60 * 24 * 3600 };
};

/**
 * Профіль підключеного акаунта (id, username) — щоб зберегти ig_id == entry.id webhook.
 */
const fetchSelf = async (token) => {
	const r = await fetch(`${GRAPH}/me?fields=user_id,username&access_token=${encodeURIComponent(token)}`);
	const j = await r.json().catch(() => ({}));
	if (!r.ok || j.error) throw new Error("SELF_FAILED");
	return { igId: String(j.user_id), username: j.username || null };
};

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
 * Деривація chat_id: HMAC-SHA256(ig_id:igsid) → перші 32 hex.
 * Детерміновано (як AES-CBC у telegram), проходить твої regex ^[a-f0-9]{32}$,
 * структура тек /assets/.../instagram/{chat_id}/ лишається ідентичною.
 */
const deriveChatId = (igId, igsid) =>
	crypto
		.createHmac("sha256", APP_SECRET || "ig")
		.update(`${igId}:${igsid}`)
		.digest("hex")
		.slice(0, 32);

/**
 * Перевірка підпису X-Hub-Signature-256 (HMAC-SHA256 сирого тіла на App Secret).
 * rawBody — Buffer (express.raw). Без цього будь-хто може слати фейкові події.
 */
const verifySignature = (rawBody, signatureHeader) => {
	if (!signatureHeader || !APP_SECRET) return false;
	const expected = "sha256=" + crypto.createHmac("sha256", APP_SECRET).update(rawBody).digest("hex");
	const a = Buffer.from(signatureHeader);
	const b = Buffer.from(expected);
	return a.length === b.length && crypto.timingSafeEqual(a, b);
};

/**
 * Резолв підключеного акаунта по ig_id (== entry.id з webhook).
 * Повертає розшифрований токен або кидає ACCOUNT_UNAVAILABLE (для відправки).
 */
const getTokenByIgId = async (igId) => {
	const [rows] = await connection_pool.execute(`SELECT id, token, active FROM ${prefix}instagram_tokens WHERE ig_id = ? LIMIT 1`, [igId]);
	if (!rows.length) throw new Error(`ACCOUNT_UNAVAILABLE:${igId}`);
	if (Number(rows[0].active) !== 1) throw new Error(`ACCOUNT_INACTIVE:${igId}`);
	return { idToken: rows[0].id, token: decryptToken(rows[0].token) };
};

/**
 * Профіль клієнта по IGSID (best-effort). Instagram Login дозволяє name/username.
 * Використовуємо глобальний fetch (Node 18+), як у твоєму telegram getMe.
 */
const fetchIgProfile = async (igsid, token) => {
	try {
		const url = `${GRAPH}/${igsid}?fields=name,username&access_token=${encodeURIComponent(token)}`;
		const r = await fetch(url);
		const j = await r.json().catch(() => ({}));
		if (j && !j.error) return { name: j.name || null, username: j.username || null };
	} catch (_) {}
	return { name: null, username: null };
};

/**
 * Контекст для відправки по chat_id: токен акаунта + igsid клієнта + вікно 24h.
 * Кидає керовані помилки, які роути маплять у 409 (як BOT_UNAVAILABLE у telegram).
 */
const getSendContextByChatId = async (chat_id) => {
	const [rows] = await connection_pool.execute(
		`SELECT ct.igsid, ct.ig_id, t.id AS id_token, t.token, t.active,
                c.last_inbound_at
           FROM ${prefix}instagram_chat_token ct
           JOIN ${prefix}instagram_tokens t ON t.ig_id = ct.ig_id
           LEFT JOIN ${prefix}instagram_conversations c ON c.chat_id = ct.chat_id
          WHERE ct.chat_id = ? LIMIT 1`,
		[chat_id]
	);
	if (!rows.length) throw new Error(`ACCOUNT_UNAVAILABLE:${chat_id}`);
	const row = rows[0];
	if (Number(row.active) !== 1) throw new Error(`ACCOUNT_INACTIVE:${chat_id}`);

	// Вікно 24 години: рахуємо від останнього вхідного
	let windowOpen = false;
	if (row.last_inbound_at) {
		const diffH = (Date.now() - new Date(row.last_inbound_at).getTime()) / 36e5;
		windowOpen = diffH < 24;
	}

	return { igsid: row.igsid, igId: row.ig_id, idToken: row.id_token, token: decryptToken(row.token), windowOpen };
};

/**
 * Надіслати текст у Instagram Direct.
 * Повертає mid відправленого повідомлення.
 */
const sendText = async (token, igsid, text) => {
	const r = await fetch(`${GRAPH}/me/messages?access_token=${encodeURIComponent(token)}`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ recipient: { id: igsid }, message: { text } }),
	});
	const j = await r.json().catch(() => ({}));
	if (!r.ok || j.error) throw igError(j);
	return j.message_id || null;
};

/**
 * Надіслати вкладення за ПУБЛІЧНИМ URL (image | video | audio | file).
 */
const sendAttachment = async (token, igsid, type, publicUrl) => {
	const r = await fetch(`${GRAPH}/me/messages?access_token=${encodeURIComponent(token)}`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ recipient: { id: igsid }, message: { attachment: { type, payload: { url: publicUrl } } } }),
	});
	const j = await r.json().catch(() => ({}));
	if (!r.ok || j.error) throw igError(j);
	return j.message_id || null;
};

// Нормалізація помилки Meta у нашу з кодом
const igError = (j) => {
	const e = j && j.error ? j.error : {};
	const err = new Error(e.message || "IG_SEND_FAILED");
	err.igCode = e.code;
	err.igSubcode = e.error_subcode;
	// код 10 / 551 тощо — вікно 24h закрите або користувач недоступний
	if (e.code === 10 || e.error_subcode === 2534022 || e.code === 551) err.windowClosed = true;
	return err;
};

/**
 * Стан акаунта для чату: чи доступний для відповіді (індикація в UI).
 */
const getAccountStatusByChatId = async (chat_id) => {
	const [rows] = await connection_pool.execute(
		`SELECT t.id, t.name, t.active
           FROM ${prefix}instagram_chat_token ct
           LEFT JOIN ${prefix}instagram_tokens t ON t.ig_id = ct.ig_id
          WHERE ct.chat_id = ? LIMIT 1`,
		[chat_id]
	);
	if (!rows.length || !rows[0].id) return { available: false, reason: "no_account" };
	if (Number(rows[0].active) !== 1) return { available: false, reason: "inactive", name: rows[0].name };
	return { available: true, name: rows[0].name };
};

/**
 * Перевірка ручного токена: чи живий і чий він (id + username).
 * Використовуємо /me на graph.instagram.com (як у твоєму зразку).
 */
const validateManualToken = async (token) => {
	const r = await fetch(`${GRAPH}/me?fields=user_id,username&access_token=${encodeURIComponent(token)}`);
	const j = await r.json().catch(() => ({}));
	if (!r.ok || j.error || !j.user_id) throw new Error(j.error?.message || "TOKEN_INVALID");
	return { igId: String(j.user_id), username: j.username || null };
};

module.exports = { prefix, GRAPH, getAccountStatusByChatId, encryptToken, decryptToken, deriveChatId, verifySignature, getTokenByIgId, fetchIgProfile, getSendContextByChatId, sendText, sendAttachment, buildAuthUrl, exchangeCode, toLongLived, refreshLongLived, fetchSelf, validateManualToken };
