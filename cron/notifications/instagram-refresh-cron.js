/**
 * Продовження довгоживучих IG-токенів.
 * Оновлюємо ті, що протухають у найближчі 10 днів.
 */
const connection_pool = require("../../config/database/connection_pool");
const logging = require("../../logging/logging");
const config = require("../../config/config");
const prefix = config.get("configDatabase").prefix;
const { decryptToken, encryptToken, refreshLongLived } = require("../../controllers/contact-center/instagram/instagram");

async function refreshTick() {
	const [rows] = await connection_pool.query(
		`SELECT id, token FROM ${prefix}instagram_tokens
          WHERE active = 1 AND token_expires_at IS NOT NULL
            AND token_expires_at < (NOW() + INTERVAL 10 DAY)`
	);
	for (const r of rows) {
		try {
			const cur = decryptToken(r.token);
			const fresh = await refreshLongLived(cur);
			const exp = new Date(Date.now() + fresh.expiresIn * 1000);
			const pad = (n) => String(n).padStart(2, "0");
			const expStr = `${exp.getFullYear()}-${pad(exp.getMonth() + 1)}-${pad(exp.getDate())} ${pad(exp.getHours())}:${pad(exp.getMinutes())}:${pad(exp.getSeconds())}`;
			await connection_pool.query(`UPDATE ${prefix}instagram_tokens SET token = ?, token_expires_at = ?, date_edit = NOW() WHERE id = ?`, [encryptToken(fresh.token), expStr, r.id]);
			console.log(`[ig-refresh] token #${r.id} продовжено до ${expStr}`);
		} catch (e) {
			logging.error(e);
			console.error(`[ig-refresh] #${r.id}:`, e.message);
		}
	}
}

module.exports = { refreshTick };
