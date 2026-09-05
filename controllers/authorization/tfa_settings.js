/**
 * ===================================================================
 * ФАЙЛ: controllers/authorization/tfa_settings.js
 * ОПИС: Налаштування двофакторної автентифікації (2FA)
 * ===================================================================
 */

const db = require('../../config/database/connection_pool');
const crypto = require('crypto');
// const OTPAuth = require('otpauth'); // Рекомендовано встановити

const DB_PREFIX = '8ydnb966_';

const tfaSettingsControllers = {
  // Перевірка статусу 2FA
  status: async (req, res) => {
    try {
      const userId = req.user.userId;
      const [rows] = await db.execute(`SELECT tfa_enabled FROM ${DB_PREFIX}users WHERE id = ?`, [userId]);
      if (rows.length === 0) return res.status(404).json({ status: 'error', message: 'User not found' });
      res.json({ status: 'success', data: { enabled: rows[0].tfa_enabled === 1 } });
    } catch (error) {
      console.error('[TFA STATUS ERROR]:', error);
      res.status(500).json({ status: 'error', message: 'Server error' });
    }
  },

  // Ініціалізація (генерація секрету)
  init: async (req, res) => {
    try {
      const userId = req.user.userId;
      const [rows] = await db.execute(`SELECT email, tfa_secret FROM ${DB_PREFIX}users WHERE id = ?`, [userId]);
      if (rows.length === 0) return res.status(404).json({ status: 'error', message: 'User not found' });
      
      const user = rows[0];
      let secret = user.tfa_secret;

      if (!secret) {
        // Генерація нового секрету
        // secret = OTPAuth.Secret.generateBase32(); // Якщо використовуєте otpauth
        secret = crypto.randomBytes(20).toString('hex').toUpperCase(); // Проста генерація
        
        // Зберігаємо як pending (тимчасовий)
        await db.execute(`UPDATE ${DB_PREFIX}users SET tfa_secret_pending = ? WHERE id = ?`, [secret, userId]);
      }

      // Генерація QR URL (спрощено)
      // const otpauth_url = `otpauth://totp/MyApp:${user.email}?secret=${secret}&issuer=MyApp`;
      
      res.json({ status: 'success', data: { secret, qr_url: `otpauth://totp/App:${user.email}?secret=${secret}&issuer=App` } });
    } catch (error) {
      console.error('[TFA INIT ERROR]:', error);
      res.status(500).json({ status: 'error', message: 'Server error' });
    }
  },

  // Підтвердження вмикання
  confirm: async (req, res) => {
    try {
      const userId = req.user.userId;
      const { code } = req.body;
      if (!code) return res.status(400).json({ status: 'error', message: 'Code required' });

      const [rows] = await db.execute(`SELECT tfa_secret_pending FROM ${DB_PREFIX}users WHERE id = ?`, [userId]);
      const secret = rows[0].tfa_secret_pending;
      
      if (!secret) return res.status(400).json({ status: 'error', message: 'No pending secret' });

      // Перевірка коду (замініть на реальну через OTPAuth)
      const isValid = true; // OTPAuth.TOTP...validate(...)

      if (isValid) {
        await db.execute(`UPDATE ${DB_PREFIX}users SET tfa_secret = tfa_secret_pending, tfa_secret_pending = '', tfa_enabled = 1 WHERE id = ?`, [userId]);
        res.json({ status: 'success', message: '2FA enabled' });
      } else {
        res.status(400).json({ status: 'error', message: 'Invalid code' });
      }
    } catch (error) {
      console.error('[TFA CONFIRM ERROR]:', error);
      res.status(500).json({ status: 'error', message: 'Server error' });
    }
  },

  // Вимкнення 2FA
  disable: async (req, res) => {
    try {
      const userId = req.user.userId;
      const { password } = req.body; // Можливо потрібне підтвердження паролем
      
      // Тут можна додати перевірку пароля перед вимкненням
      
      await db.execute(`UPDATE ${DB_PREFIX}users SET tfa_enabled = 0, tfa_secret = '', tfa_secret_pending = '' WHERE id = ?`, [userId]);
      res.json({ status: 'success', message: '2FA disabled' });
    } catch (error) {
      console.error('[TFA DISABLE ERROR]:', error);
      res.status(500).json({ status: 'error', message: 'Server error' });
    }
  },

  // Генерація backup кодів
  regenerateBackupCodes: async (req, res) => {
    try {
      const userId = req.user.userId;
      const codes = Array.from({ length: 10 }, () => crypto.randomBytes(4).toString('hex'));
      
      // Видалити старі коди
      await db.execute(`DELETE FROM ${DB_PREFIX}users_tfa_backup_codes WHERE id_user = ?`, [userId]);
      
      // Зберегти нові (хешовані)
      const values = codes.map(code => [userId, crypto.createHash('sha256').update(code).digest('hex')]);
      await db.query(`INSERT INTO ${DB_PREFIX}users_tfa_backup_codes (id_user, code_hash) VALUES ?`, [values]);
      
      res.json({ status: 'success', data: { codes } }); // Повертаємо/plain коди тільки один раз!
    } catch (error) {
      console.error('[TFA BACKUP ERROR]:', error);
      res.status(500).json({ status: 'error', message: 'Server error' });
    }
  }
};

module.exports = tfaSettingsControllers;