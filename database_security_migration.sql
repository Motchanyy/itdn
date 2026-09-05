-- =============================================================================
-- 🛡️ БЕЗПЕЧНІСТЬ БАЗИ ДАНИХ: МІГРАЦІЯ ДЛЯ ЗАХИСТУ АВТОРИЗАЦІЇ
-- =============================================================================
-- 
-- Цей SQL скрипт додає необхідні колонки та таблиці для реалізації
-- максимального рівня безпеки в системі авторизації.
-- 
-- Реалізовані заходи:
-- 1. ✅ Відстеження невдалих спроб входу
-- 2. ✅ Блокування акаунтів після перебору паролів
-- 3. ✅ Логування всіх подій безпеки
-- 4. ✅ Відстеження пристроїв та IP адрес
-- 5. ✅ Підтримка 2FA (двофакторна аутентифікація)
-- 6. ✅ Token versioning для примусового логауту
-- 
-- @version 2.0.0
-- @security MAXIMUM
-- =============================================================================

-- =============================================================================
-- ЧАСТИНА 1: МОДИФІКАЦІЯ ТАБЛИЦІ `users`
-- =============================================================================
-- Додаємо колонки для відстеження спроб входу та безпеки

-- Додаємо лічильник невдалих спроб входу
ALTER TABLE `users` 
ADD COLUMN IF NOT EXISTS `failed_login_attempts` INT DEFAULT 0 COMMENT 'Кількість невдалих спроб входу' AFTER `password`;

-- Додаємо час блокування акаунту
ALTER TABLE `users` 
ADD COLUMN IF NOT EXISTS `locked_until` DATETIME NULL DEFAULT NULL COMMENT 'Час закінчення блокування акаунту' AFTER `failed_login_attempts`;

-- Додаємо час останньої невдалої спроби
ALTER TABLE `users` 
ADD COLUMN IF NOT EXISTS `last_failed_attempt` DATETIME NULL DEFAULT NULL COMMENT 'Час останньої невдалої спроби входу' AFTER `locked_until`;

-- Додаємо IP останнього успішного входу
ALTER TABLE `users` 
ADD COLUMN IF NOT EXISTS `last_login_ip` VARCHAR(45) NULL DEFAULT NULL COMMENT 'IP адреса останнього успішного входу' AFTER `last_failed_attempt`;

-- Додаємо тип останнього пристрою (0=desktop, 1=mobile, 2=tablet)
ALTER TABLE `users` 
ADD COLUMN IF NOT EXISTS `last_device_type` TINYINT DEFAULT 0 COMMENT 'Тип пристрою останнього входу: 0=desktop, 1=mobile, 2=tablet' AFTER `last_login_ip`;

-- Додаємо час останнього успішного входу
ALTER TABLE `users` 
ADD COLUMN IF NOT EXISTS `last_login_time` DATETIME NULL DEFAULT NULL COMMENT 'Час останнього успішного входу' AFTER `last_device_type`;

-- Додаємо версію токена для примусового логауту всіх сесій
ALTER TABLE `users` 
ADD COLUMN IF NOT EXISTS `token_version` INT DEFAULT 1 COMMENT 'Версія токена для інвалідації сесій' AFTER `last_login_time`;

-- Додаємо прапорець увімкненої 2FA
ALTER TABLE `users` 
ADD COLUMN IF NOT EXISTS `tfa_enabled` TINYINT(1) DEFAULT 0 COMMENT 'Чи увімкнено двофакторну аутентифікацію' AFTER `token_version`;

-- Додаємо секретний ключ 2FA
ALTER TABLE `users` 
ADD COLUMN IF NOT EXISTS `tfa_secret` VARCHAR(255) NULL DEFAULT NULL COMMENT 'Секретний ключ для 2FA' AFTER `tfa_enabled`;

-- Додаємо лічильник невдалих спроб 2FA
ALTER TABLE `users` 
ADD COLUMN IF NOT EXISTS `tfa_failed_attempts` INT DEFAULT 0 COMMENT 'Кількість невдалих спроб введення 2FA коду' AFTER `tfa_secret`;

-- Додаємо час блокування 2FA
ALTER TABLE `users` 
ADD COLUMN IF NOT EXISTS `tfa_locked_until` DATETIME NULL DEFAULT NULL COMMENT 'Час закінчення блокування 2FA' AFTER `tfa_failed_attempts`;

-- Додаємо дату останньої спроби 2FA
ALTER TABLE `users` 
ADD COLUMN IF NOT EXISTS `tfa_last_step` INT DEFAULT 0 COMMENT 'Останній крок налаштування 2FA' AFTER `tfa_locked_until`;

-- Додаємо дату останнього успішного входу (альтернативне поле)
ALTER TABLE `users` 
ADD COLUMN IF NOT EXISTS `date_last_login` DATETIME NULL DEFAULT NULL COMMENT 'Дата останнього успішного входу' AFTER `tfa_last_step`;

-- Створюємо індекси для прискорення запитів
CREATE INDEX IF NOT EXISTS `idx_users_email` ON `users`(`email`);
CREATE INDEX IF NOT EXISTS `idx_users_active` ON `users`(`active`);
CREATE INDEX IF NOT EXISTS `idx_users_locked` ON `users`(`locked_until`);

-- =============================================================================
-- ЧАСТИНА 2: ТАБЛИЦЯ ДЛЯ ЗБЕРІГАННЯ ПОДІЙ БЕЗПЕКИ
-- =============================================================================
-- Логує всі важливі події: входи, зміни паролю, 2FA тощо

CREATE TABLE IF NOT EXISTS `users_security_events` (
  `id` BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT 'Унікальний ID події',
  
  `id_user` INT NULL DEFAULT NULL COMMENT 'ID користувача (NULL якщо користувач не знайдений)',
  
  `event_type` ENUM(
    'login_success',              -- Успішний вхід
    'login_failed',               -- Невдалий вхід (невірний пароль)
    'login_failed_unknown_user',  -- Спроба входу з неіснуючим email
    'login_blocked',              -- Спроба входу заблокованого акаунту
    'login_inactive',             -- Спроба входу неактивного акаунту
    'login_failed_invalid_2fa',   -- Невірний 2FA код
    'login_new_device_or_ip',     -- Вхід з нового пристрою/IP
    'login_system_error',         -- Системна помилка при вході
    'invalid_request',            -- Недійсний запит (валідація не пройшла)
    'password_changed',           -- Зміна паролю
    'password_reset_requested',   -- Запит на скидання паролю
    '2fa_enabled',                -- Увімкнення 2FA
    '2fa_disabled',               -- Вимкнення 2FA
    '2fa_backup_code_used',       -- Використання backup коду 2FA
    'suspicious_activity'         -- Підозріла активність
  ) NOT NULL COMMENT 'Тип події безпеки',
  
  `ip` VARCHAR(45) NOT NULL COMMENT 'IP адреса з якої сталася подія',
  
  `user_agent` VARCHAR(512) NULL DEFAULT NULL COMMENT 'User-Agent браузера',
  
  `extra_data` JSON NULL DEFAULT NULL COMMENT 'Додаткові дані події в форматі JSON',
  
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Час створення запису',
  
  -- Індекси для швидкого пошуку
  INDEX `idx_user_event` (`id_user`, `event_type`),
  INDEX `idx_created_at` (`created_at`),
  INDEX `idx_ip_address` (`ip`),
  INDEX `idx_event_type` (`event_type`)
  
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci 
COMMENT='Таблиця для логування подій безпеки користувачів';

-- =============================================================================
-- ЧАСТИНА 3: ТАБЛИЦЯ ЛОГІВ ВХОДУ
-- =============================================================================
-- Детальна історія всіх спроб входу (успішних та неуспішних)

CREATE TABLE IF NOT EXISTS `users_login_log` (
  `id` BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT 'Унікальний ID запису',
  
  `id_user` INT NOT NULL COMMENT 'ID користувача',
  
  `ip` VARCHAR(45) NOT NULL COMMENT 'IP адреса з якої була спроба входу',
  
  `user_agent` VARCHAR(512) NULL DEFAULT NULL COMMENT 'User-Agent браузера',
  
  `device` TINYINT DEFAULT 0 COMMENT 'Тип пристрою: 0=desktop, 1=mobile, 2=tablet',
  
  `status` TINYINT(1) DEFAULT 0 COMMENT 'Статус входу: 1=успішно, 0=неуспішно',
  
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Час спроби входу',
  
  -- Індекси для аналізу
  INDEX `idx_user_login` (`id_user`),
  INDEX `idx_status` (`status`),
  INDEX `idx_created` (`created_at`)
  
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Лог всіх спроб входу користувачів';

-- =============================================================================
-- ЧАСТИНА 4: ТАБЛИЦЯ BACKUP КОДІВ 2FA
-- =============================================================================
-- Резервні коди для відновлення доступу при втраті 2FA пристрою

CREATE TABLE IF NOT EXISTS `users_tfa_backup_codes` (
  `id` BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT 'Унікальний ID коду',
  
  `id_user` INT NOT NULL COMMENT 'ID користувача якому належить код',
  
  `code_hash` VARCHAR(255) NOT NULL COMMENT 'Хеш резервного коду (SHA-256)',
  
  `used_at` DATETIME NULL DEFAULT NULL COMMENT 'Час використання коду (NULL якщо не використаний)',
  
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Час створення коду',
  
  -- Унікальність коду
  UNIQUE KEY `unique_code_hash` (`code_hash`),
  
  -- Індекси для пошуку
  INDEX `idx_user_codes` (`id_user`),
  INDEX `idx_unused_codes` (`used_at`)
  
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Резервні коди для двофакторної аутентифікації';

-- =============================================================================
-- ЧАСТИНА 5: ТАБЛИЦЯ ЗАПРОШЕНЬ (INVITES)
-- =============================================================================
-- Для реєстрації по запрошенню (адміністратор створює інвайт)

CREATE TABLE IF NOT EXISTS `users_invites` (
  `id` BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT 'Унікальний ID запрошення',
  
  `email` VARCHAR(255) NOT NULL COMMENT 'Email на який надіслано запрошення',
  
  `token` VARCHAR(96) NOT NULL COMMENT 'Унікальний токен запрошення (96 символів)',
  
  `id_group` INT NULL DEFAULT NULL COMMENT 'ID групи в яку буде додано користувача',
  
  `status` TINYINT(1) DEFAULT 0 COMMENT 'Статус: 0=очікує, 1=використано, 2=скасовано',
  
  `expires_at` DATETIME NOT NULL COMMENT 'Час закінчення терміну дії запрошення',
  
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Час створення запрошення',
  
  `date_accepted` DATETIME NULL DEFAULT NULL COMMENT 'Час прийняття запрошення',
  
  -- Унікальність токена
  UNIQUE KEY `unique_token` (`token`),
  
  -- Індекси для пошуку
  INDEX `idx_email` (`email`),
  INDEX `idx_status` (`status`),
  INDEX `idx_expires` (`expires_at`)
  
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Запрошення для реєстрації користувачів';

-- =============================================================================
-- ЧАСТИНА 6: ТАБЛИЦЯ СКИДАННЯ ПАРОЛЮ
-- =============================================================================
-- Токени для скидання паролю через email

CREATE TABLE IF NOT EXISTS `users_password_resets` (
  `id` BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT 'Унікальний ID запису',
  
  `email` VARCHAR(255) NOT NULL COMMENT 'Email для якого створено токен',
  
  `token` VARCHAR(255) NOT NULL COMMENT 'Унікальний токен скидання паролю',
  
  `expires_at` DATETIME NOT NULL COMMENT 'Час закінчення терміну дії токена',
  
  `used` TINYINT(1) DEFAULT 0 COMMENT 'Чи використано токен: 0=ні, 1=так',
  
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Час створення токена',
  
  -- Індекси для пошуку
  INDEX `idx_email_token` (`email`, `token`),
  INDEX `idx_expires` (`expires_at`),
  INDEX `idx_used` (`used`)
  
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Токени для скидання паролю';

-- =============================================================================
-- ЧАСТИНА 7: ТАБЛИЦЯ СЕСІЙ КОРИСТУВАЧІВ
-- =============================================================================
-- Активні сесії користувачів для управління пристроями

CREATE TABLE IF NOT EXISTS `users_sessions` (
  `id` BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT 'Унікальний ID сесії',
  
  `id_user` INT NOT NULL COMMENT 'ID користувача',
  
  `ip_address` VARCHAR(45) NOT NULL COMMENT 'IP адреса з якої створено сесію',
  
  `user_agent` VARCHAR(512) NOT NULL COMMENT 'User-Agent браузера',
  
  `device_fingerprint` VARCHAR(64) NULL DEFAULT NULL COMMENT 'Унікальний відбиток пристрою',
  
  `refresh_token_hash` VARCHAR(255) NULL DEFAULT NULL COMMENT 'Хеш refresh токена',
  
  `is_valid` TINYINT(1) DEFAULT 1 COMMENT 'Чи дійсна сесія: 1=так, 0=ні (виведена з ладу)',
  
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Час створення сесії',
  
  `expires_at` DATETIME NOT NULL COMMENT 'Час закінчення терміну дії сесії',
  
  `last_activity` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Час останньої активності',
  
  -- Індекси для управління сесіями
  INDEX `idx_user_sessions` (`id_user`),
  INDEX `idx_valid_sessions` (`is_valid`, `expires_at`),
  INDEX `idx_refresh_token` (`refresh_token_hash`),
  INDEX `idx_last_activity` (`last_activity`)
  
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Активні сесії користувачів';

-- =============================================================================
-- ЧАСТИНА 8: ДОДАТКОВІ ІНДЕКСИ ДЛЯ ПРОДУКТИВНОСТІ
-- =============================================================================

-- Індекси для таблиці users (якщо ще не створені)
CREATE INDEX IF NOT EXISTS `idx_users_token_version` ON `users`(`token_version`);
CREATE INDEX IF NOT EXISTS `idx_users_tfa` ON `users`(`tfa_enabled`, `tfa_secret`);

-- =============================================================================
-- ЧАСТИНА 9: ПРИКЛАДИ ВИКОРИСТАННЯ
-- =============================================================================
-- 
-- 1. Перевірка користувача при вході:
--    SELECT id, email, password, active, failed_login_attempts, locked_until,
--           tfa_enabled, tfa_secret, token_version
--    FROM users WHERE email = ? LIMIT 1;
-- 
-- 2. Оновлення після невдалої спроби:
--    UPDATE users 
--    SET failed_login_attempts = failed_login_attempts + 1,
--        last_failed_attempt = NOW(),
--        locked_until = CASE 
--          WHEN failed_login_attempts + 1 >= 5 
--          THEN DATE_ADD(NOW(), INTERVAL 15 MINUTE)
--          ELSE NULL 
--        END
--    WHERE id = ?;
-- 
-- 3. Логування події безпеки:
--    INSERT INTO users_security_events (id_user, event_type, ip, user_agent, extra_data)
--    VALUES (?, 'login_failed', ?, ?, ?);
-- 
-- 4. Отримання історії входів користувача:
--    SELECT * FROM users_login_log 
--    WHERE id_user = ? 
--    ORDER BY created_at DESC 
--    LIMIT 50;
-- 
-- 5. Видалення старих сесій:
--    DELETE FROM users_sessions 
--    WHERE expires_at < NOW() OR is_valid = 0;
-- 
-- =============================================================================
-- ЗАВЕРШЕННЯ МІГРАЦІЇ
-- =============================================================================

SELECT '✅ Міграція безпеки успішно завершена!' AS status;
SELECT 'Перевірте таблиці:' AS info;
SELECT ' - users (додані колонки для безпеки)' AS table_name;
SELECT ' - users_security_events (логі подій)' AS table_name;
SELECT ' - users_login_log (історія входів)' AS table_name;
SELECT ' - users_tfa_backup_codes (2FA backup коди)' AS table_name;
SELECT ' - users_invites (запрошення)' AS table_name;
SELECT ' - users_password_resets (скидання паролю)' AS table_name;
SELECT ' - users_sessions (активні сесії)' AS table_name;
