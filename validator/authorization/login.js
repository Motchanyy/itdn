/**
 * ===================================================================
 * ФАЙЛ: validators/authorization/login.js
 * ОПИС: AJV схема валідації для входу
 * ЗАХИСТ: Mass Assignment, XSS, Injection
 * ===================================================================
 */

const Ajv = require('ajv').default;
const addFormats = require('ajv-formats');

const ajv = new Ajv({
  allErrors: true,
  strict: true,
  coerceTypes: false, // Не приводити типи автоматично
  removeAdditional: false // Не видаляти додаткові поля (ми їх відхиляємо)
});

addFormats(ajv);

const loginSchema = {
  type: 'object',
  required: ['email', 'password'],
  additionalProperties: false, // Заборона будь-яких зайвих полів
  properties: {
    email: {
      type: 'string',
      format: 'email',
      minLength: 6,
      maxLength: 255,
      pattern: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'
    },
    password: {
      type: 'string',
      minLength: 8,
      maxLength: 128
      // Додатково можна додати pattern для складності пароля
    },
    two_factor_code: {
      type: 'string',
      nullable: true,
      pattern: '^\\d{6}$',
      minLength: 6,
      maxLength: 6
    },
    remember_me: {
      type: 'boolean',
      default: false
    }
  }
};

const validateLogin = ajv.compile(loginSchema);

function validateLoginInput(data) {
  if (!data || typeof data !== 'object') {
    return { 
      valid: false, 
      errors: [{ field: 'body', message: 'Request body must be a valid JSON object' }] 
    };
  }

  const valid = validateLogin(data);

  if (!valid) {
    const formattedErrors = validateLogin.errors.map(err => ({
      field: err.instancePath.substring(1) || 'root',
      message: err.message === 'must NOT have additional properties' 
        ? 'Unknown field provided' 
        : err.message,
      keyword: err.keyword
    }));
    return { valid: false, errors: formattedErrors };
  }

  return { valid: true, errors: null };
}

module.exports = {
  validateLoginInput,
  validateLogin,
  loginSchema
};