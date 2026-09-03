const config = require("../../config/config");
const configDatabase = config.get("configDatabase");
const logging = require("../../logging/logging");
const P = configDatabase.prefix;

// Поставити зміну в чергу CRM→сайт. Викликати ТІЛЬКИ для ручних змін оператора.
// conn — активне з'єднання транзакції (емісія — частина тієї ж транзакції, що й зміна).
const emitToOutbox = async (conn, { id_order, event_type, data }) => {
  // Дізнаємось інтеграцію та external_id замовлення
  const [[o]] = await conn.query(
    `SELECT id_integration, external_id FROM \`${P}orders\` WHERE id = ? LIMIT 1`,
    [id_order],
  );
  // Немає інтеграції або external_id → нема куди/що слати (напр. замовлення створене вручну в CRM)
  if (!o || !o.id_integration || !o.external_id) return;

  await conn.query(
    `INSERT INTO \`${P}orders_outbox\`
      (id_integration, id_order, external_id, event_type, payload, status, date_add)
     VALUES (?, ?, ?, ?, ?, 'pending', NOW())`,
    [o.id_integration, id_order, o.external_id, event_type, JSON.stringify(data)],
  );
};

module.exports = { emitToOutbox };