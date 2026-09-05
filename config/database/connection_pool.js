/**
 * =============================================================================
 * БАЗА ДАНИХ: CONNECTION POOL
 * =============================================================================
 * 
 * Цей файл створює пул з'єднань з MySQL для оптимізації продуктивності.
 * Пул дозволяє уникнути накладних витрат на створення нового з'єднання
 * для кожного запиту.
 * 
 * @version 1.0.0
 */

"use strict";

const mysql = require("mysql2/promise");
require("dotenv").config();

// =============================================================================
 * КОНФІГУРАЦІЯ ПІДКЛЮЧЕННЯ
 * =============================================================================
 * 
 * Використовуємо змінні оточення для безпеки:
 * - DB_HOST: хост бази даних
 * - DB_USER: користувач
 * - DB_PASSWORD: пароль
 * - DB_NAME: ім'я бази даних
 * - DB_PORT: порт (за замовчуванням 3306)
 */

const dbConfig = {
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "my_database",
  port: process.env.DB_PORT || 3306,
  
  // Налаштування пулу з'єднань
  waitForConnections: true,    // Чекати якщо немає вільних з'єднань
  connectionLimit: 10,         // Максимум 10 одночасних з'єднань
  queueLimit: 0,               // Без обмеження черги
  enableKeepAlive: true,       // Зберігати з'єднання активними
  keepAliveInitialDelay: 0,    // Затримка keepalive
  
  // Кодування для підтримки Unicode
  charset: "utf8mb4",
  timezone: "+00:00",          // UTC час
  
  // Безпека: ігноруємо локальні файли
  localInfile: false
};

// Створення пулу з'єднань
const pool = mysql.createPool(dbConfig);

// =============================================================================
 * ПЕРЕВІРКА ПІДКЛЮЧЕННЯ
 * =============================================================================
 * 
 * Перевіряємо чи можемо підключитися до БД при старті
 */

pool.getConnection()
  .then(connection => {
    console.log("✅ Database connected successfully");
    console.log(`   Host: ${dbConfig.host}:${dbConfig.port}`);
    console.log(`   Database: ${dbConfig.database}`);
    console.log(`   Pool size: ${dbConfig.connectionLimit}`);
    
    // Звільняємо з'єднання (повертаємо в пул)
    connection.release();
  })
  .catch(error => {
    console.error("❌ Database connection error:", error.message);
    console.error("   Please check your environment variables:");
    console.error("   - DB_HOST");
    console.error("   - DB_USER");
    console.error("   - DB_PASSWORD");
    console.error("   - DB_NAME");
    console.error("   - DB_PORT");
  });

// =============================================================================
 * ОБРОБКА ПОМИЛОК ПУЛУ
 * =============================================================================
 * 
 * Логуємо помилки які виникають під час роботи пулу
 */

pool.on("error", (err) => {
  console.error("[DB Pool Error]", err);
  
  // Якщо з'єднання втрачено, намагаємось відновити
  if (err.code === "PROTOCOL_CONNECTION_LOST") {
    console.warn("Database connection lost. Attempting to reconnect...");
  }
  
  // Критичні помилки
  if (err.code === "ER_ACCESS_DENIED_ERROR") {
    console.error("Access denied. Check DB credentials.");
  }
  
  if (err.code === "ENOTFOUND") {
    console.error("Database host not found. Check DB_HOST.");
  }
});

// =============================================================================
 * ЕКСПОРТ
 * =============================================================================
 * 
 * Експортуємо пул для використання в контролерах
 * 
 * Приклад використання:
 * const connection_pool = require("./config/database/connection_pool");
 * 
 * // Виконання запиту
 * const [rows] = await connection_pool.query("SELECT * FROM users WHERE id = ?", [userId]);
 * 
 * // Використання транзакції
 * const connection = await connection_pool.getConnection();
 * try {
 *   await connection.beginTransaction();
 *   await connection.query("UPDATE accounts SET balance = balance - ? WHERE id = ?", [amount, fromId]);
 *   await connection.query("UPDATE accounts SET balance = balance + ? WHERE id = ?", [amount, toId]);
 *   await connection.commit();
 * } catch (err) {
 *   await connection.rollback();
 *   throw err;
 * } finally {
 *   connection.release();
 * }
 */

module.exports = pool;
