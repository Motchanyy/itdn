/**
 * =============================================================================
 * 🛡️ ВАЛІДАТОР LOGIN З МАКСИМАЛЬНИМ РІВНЕМ БЕЗПЕКИ (AJV)
 * =============================================================================
 * 
 * Цей файл відповідає за сувору валідацію всіх вхідних даних для форми логіну.
 * Використовується бібліотека AJV (Another JSON Schema Validator) для створення
 * строгої схеми валідації.
 * 
 * 🔐 Реалізовані заходи безпеки:
 * 1. ✅ Строга типізація всіх полів (coerceTypes: false)
 * 2. ✅ Перевірка email формату + regex патерн
 * 3. ✅ Обмеження довжини полів (захист від переповнення)
 * 4. ✅ Додатковий regex для email (захист від IDN homograph attacks)
 * 5. ✅ 2FA код - рівно 6 цифр (regex перевірка)
 * 6. ✅ additionalProperties: false (відхиляє невідомі поля)
 * 7. ✅ Заборона автоматичного приведення типів
 * 
 * @version 2.0.0
 * @security MAXIMUM
 */

"use strict";

// Імпорт бібліотек для валідації
const Ajv = require("ajv").default;        // JSON Schema validator
const addFormats = require("ajv-formats"); // Додаткові формати (email, date тощо)

// ===========================================================================
 * ІНІЦІАЛІЗАЦІЯ AJV З НАЛАШТУВАННЯМИ БЕЗПЕКИ
 * ===========================================================================
 * 
 * allErrors: true - збирати всі помилки, а не зупинятися на першій
 * strict: true - суворий режим для виявлення проблем у схемі
 * coerceTypes: false - КРИТИЧНО: забороняємо авто-приведення типів
 *                      Наприклад: "true" (string) не стане true (boolean)
 *                      Це запобігає атакам типу "type confusion"
 */
const ajv = new Ajv({ 
  allErrors: true, 
  strict: true, 
  coerceTypes: false // ЗАБОРОНА автоматичного приведення типів
});

// Додаємо підтримку форматів (email, uri, date-time тощо)
addFormats(ajv);

// ===========================================================================
 * СХЕМА ВАЛІДАЦІЇ ДЛЯ ЛОГІНУ
 * ===========================================================================
 * 
 * Кожен field має:
 * - type: строгий тип даних
 * - minLength/maxLength: обмеження довжини
 * - pattern: regex для додаткової перевірки
 * - format: стандартний формат (email)
 * 
 * additionalProperties: false - КРИТИЧНО ВАЖЛИВО!
 * Це означає що будь-які невідомі поля будуть відхилені.
 * Запобігає атакам типу:
 * - Mass Assignment (спроба передати isAdmin, role тощо)
 * - NoSQL Injection (спроба передати $where, $ne тощо)
 * - Prototype Pollution
 */
const loginSchema = {
  type: "object",
  
  properties: {
    /**
     * EMAIL КОРИСТУВАЧА
     * 
     * Подвійна перевірка:
     * 1. format: "email" - стандартна перевірка RFC 5322
     * 2. pattern - додатковий regex для захисту від:
     *    - IDN homograph attacks (використання схожих символів)
     *    - Спеціальних символів які можуть зламати SQL запит
     * 
     * Довжина: 6-255 символів (стандарт для більшості БД)
     */
    email: {
      type: "string",
      format: "email",                    // Стандартний email формат
      minLength: 6,                       // Мінімум 6 символів (a@b.co)
      maxLength: 255,                     // Максимум для сумісності з БД
      // Regex дозволяє тільки ASCII символи в email
      // Захищає від IDN homograph attacks (наприклад, using Cyrillic 'а' instead of Latin 'a')
      pattern: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    },
    
    /**
     * ПАРОЛЬ КОРИСТУВАЧА
     * 
     * Вимоги до паролю:
     * - Мінімум 8 символів (базовий рівень)
     * - Максимум 128 символів (захист від DoS через довгі рядки)
     * 
     * Примітка: Повна перевірка складності паролю
     * (великі літери, цифри, спецсимволи) виконується
     * в логіці контролера або при реєстрації.
     * Тут тільки базова перевірка довжини.
     */
    password: {
      type: "string",
      minLength: 8,                       // Мінімум 8 символів
      maxLength: 128,                     // Максимум для захисту від DoS
      // Можна додати pattern для вимоги складності, але краще в контролері
      // pattern: "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$"
    },
    
    /**
     * 2FA КОД (ОПЦІОНАЛЬНО)
     * 
     * Використовується коли увімкнено двофакторну аутентифікацію.
     * 
     * Вимоги:
     * - Рівно 6 цифр (0-9)
     * - Опціональне поле (може бути відсутнім)
     * - nullable: true дозволяє null значення
     * 
     * pattern: "^[0-9]{6}$" гарантує:
     * - Тільки цифри (ніяких літер чи спецсимволів)
     * - Рівно 6 символів (не більше, не менше)
     */
    tfa_code: {
      type: "string",
      pattern: "^[0-9]{6}$",             // Рівно 6 цифр
      nullable: true                      // Поле не є обов'язковим
    },
    
    /**
     * ЗАПАМ'ЯТАТИ ПРИСТРІЙ
     * 
     * Булеве значення для подовження сесії.
     * 
     * Важливо: coerceTypes: false означає що:
     * - "true" (string) НЕ буде приведено до true (boolean)
     * - "false" (string) НЕ буде приведено до false (boolean)
     * - 1 (number) НЕ буде приведено до true (boolean)
     * - 0 (number) НЕ буде приведено до false (boolean)
     * 
     * Це запобігає атакам де зловмисник намагається
     * обманути систему передаючи рядок замість boolean.
     */
    remember_me: {
      type: "boolean",                    // Тільки справжній boolean
      default: false                      // За замовчуванням false
    },
    
    /**
     * FINGERPRINT ПРИСТРОЮ (ОПЦІОНАЛЬНО)
     * 
     * Хеш пристрою для відстеження сесій.
     * Генерується на клієнті за допомогою бібліотек
     * типу FingerprintJS.
     * 
     * maxLength: 64 символи (SHA-256 дає 64 hex символи)
     */
    fingerprint: {
      type: "string",
      maxLength: 64,                      // Максимум 64 символи (SHA-256 hash)
      nullable: true                      // Поле не є обов'язковим
    }
  },
  
  // Обов'язкові поля (без них валідація не пройде)
  required: ["email", "password"],
  
  // КРИТИЧНО: Відхиляє будь-які інші поля які не вказані вище
  // Це запобігає:
  // 1. Mass Assignment attacks (спроба передати isAdmin, role, permissions)
  // 2. NoSQL Injection (спроба передати $where, $gt, $ne тощо)
  // 3. Prototype Pollution (спроба передати __proto__, constructor)
  // 4. Будь-яким іншим невідомим полям
  additionalProperties: false
};

// Компилюємо схему для оптимальної продуктивності
// (AJV компілює схему в швидку JavaScript функцію)
const validateLoginCompiled = ajv.compile(loginSchema);

/**
 * Функція валідації даних логіну
 * 
 * @param {Object} data - Дані для валідації (зазвичай req.body)
 * @returns {Array|null} - Масив помилок або null якщо все добре
 * 
 * Приклад використання:
 * const errors = validateLogin(req.body);
 * if (errors) {
 *   return res.status(422).json({ status: "error", errors });
 * }
 * 
 * Приклад помилок які повертає:
 * [
 *   {
 *     instancePath: "/email",
 *     keyword: "format",
 *     message: "must match format \"email\"",
 *     params: { format: "email" }
 *   },
 *   {
 *     instancePath: "",
 *     keyword: "additionalProperties",
 *     message: "must NOT have additional properties",
 *     params: { additionalProperty: "isAdmin" }
 *   }
 * ]
 */
function validateLogin(data) {
  // Виконуємо валідацію
  const valid = validateLoginCompiled(data);
  
  // Якщо є помилки - повертаємо їх
  if (!valid && validateLoginCompiled.errors) {
    return validateLoginCompiled.errors;
  }
  
  // Якщо все добре - повертаємо null
  return null;
}

// Експортуємо функцію валідації
module.exports = validateLogin;
