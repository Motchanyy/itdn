const jwt = require("jsonwebtoken");
const bcryptjs = require("bcryptjs");
const crypto = require("crypto");
const validator = require("validator");

// Конфігурація
const config = require("../../../../config/config");
const configDatabase = config.get("configDatabase");
const jwtConfig = config.get("configJWT");
// END Конфігурація

// logging
const logging = require("../../../../logging/logging");
// END logging

//
const i18n = require("../../../../config/i18n/i18n");
//

//Database connection
const connection = require("../../../../config/database/database");
//END Database connection

// Утиліти для роботи з email
const emailUtils = require("../../../../utils/email-utils");
// END Утиліти для роботи з email

// Валідатор
//const validator_login = require("../../validator/authorization/login");
//const validator_register = require("../../validator/authorization/register");
// END Валідатор

// Функція для відправки email для скидання паролю
const sendPasswordResetEmail = async (email, resetURL) => {
  try {
    // Отримуємо HTML-шаблон для листа
    const htmlTemplate = emailUtils.getEmailTemplate("reset-password", {
      resetURL: resetURL,
    });

    // Створюємо транспорт для відправки email
    const transporter = nodemailer.createTransport({
      host: emailConfig.host,
      port: emailConfig.port,
      secure: emailConfig.secure,
      auth: {
        user: emailConfig.user,
        pass: emailConfig.password,
      },
    });

    // Налаштування email
    const mailOptions = {
      from: `"${emailConfig.from_name}" <${emailConfig.from_email}>`,
      to: email,
      subject: "Скидання паролю",
      html: htmlTemplate,
    };

    // Відправляємо email
    await transporter.sendMail(mailOptions);

    logging.info(`Лист для скидання паролю успішно відправлено на адресу: ${email}`);
  } catch (error) {
    logging.error(`Помилка при відправленні листа для скидання паролю: ${error}`);
    throw error;
  }
};
// END Функція для відправки email для скидання паролю

// Авторизація
const blockedIPs = {}; // Словник для зберігання заблокованих IP
const MAX_ATTEMPTS = 5; // Максимальна кількість спроб входу
const BLOCK_TIME = 5 * 60 * 1000; // Час блокування в мілісекундах
const ATTEMPT_WINDOW = 5 * 60 * 1000; // Вікно часу для відстеження невдалих спроб

exports.login = async (req, res) => {
  try {
    const email = req.body.email;
    const password = req.body.password;
    const remember_me = req.body.remember_me;
    const clientIP = req.ip;

    // Перевірка на блокування
    if (blockedIPs[clientIP]) {
      if (blockedIPs[clientIP].expires && Date.now() < blockedIPs[clientIP].expires) {
        const expires = blockedIPs[clientIP].expires - Date.now();
        const minutes = Math.floor(expires / 60000);
        const seconds = Math.floor((expires % 60000) / 1000);

        return res.status(403).json({
          status: "blocked",
          message: res.__("authorization.error.authorization_blocked", { minutes, seconds }),
        });
      } else if (blockedIPs[clientIP].expires && Date.now() >= blockedIPs[clientIP].expires) {
        // Якщо час блокування минув, видаляємо IP зі списку заблокованих
        delete blockedIPs[clientIP];
      }
    }

    const errors = [];
    if (!validator.isEmail(email)) {
      errors.push({
        error: "email",
        message: res.__("authorization.error.please_fill_out_this_field"), // Переклад повідомлення
      });
    }

    if (validator.isEmpty(password)) {
      errors.push({
        error: "password",
        message: res.__("authorization.error.please_fill_out_this_field"), // Переклад повідомлення
      });
    }

    // Якщо є помилки, збільшуємо лічильник невдалих спроб
    if (errors.length > 0) {
      if (!blockedIPs[clientIP]) {
        blockedIPs[clientIP] = { attempts: 0, expires: null, timestamps: [] };
      }

      blockedIPs[clientIP].attempts++;

      // Додаємо timestamp до масиву
      blockedIPs[clientIP].timestamps.push(Date.now());

      // Очищуємо старі спроби, які виходять за межі вікна часу
      blockedIPs[clientIP].timestamps = blockedIPs[clientIP].timestamps.filter((timestamp) => {
        return timestamp > Date.now() - ATTEMPT_WINDOW;
      });

      if (blockedIPs[clientIP].attempts >= MAX_ATTEMPTS) {
        blockedIPs[clientIP].expires = Date.now() + BLOCK_TIME;
        const minutes = "5";
        const seconds = "0";
        return res.status(403).json({
          status: "blocked",
          message: res.__("authorization.error.authorization_blocked", { minutes, seconds }),
        });
      }

      return res.status(400).json({ status: "error", errors });
    }

    connection.query("SELECT * FROM " + configDatabase.prefix + "users WHERE email = ?", [email], async (error, results) => {
      if (error) {
        return res.status(500).json({ status: "error", message: res.__("Внутрішня помилка сервера.") });
      }

      if (results.length === 0 || !(await bcryptjs.compare(password, results[0].password))) {
        // Обробка невдалої спроби входу
        if (!blockedIPs[clientIP]) {
          blockedIPs[clientIP] = { attempts: 0, expires: null, timestamps: [] };
        }

        blockedIPs[clientIP].attempts++;

        // Додаємо timestamp до масиву
        blockedIPs[clientIP].timestamps.push(Date.now());

        // Очищуємо старі спроби
        blockedIPs[clientIP].timestamps = blockedIPs[clientIP].timestamps.filter((timestamp) => {
          return timestamp > Date.now() - ATTEMPT_WINDOW;
        });

        if (blockedIPs[clientIP].attempts >= MAX_ATTEMPTS) {
          blockedIPs[clientIP].expires = Date.now() + BLOCK_TIME;
          return res.status(403).json({
            status: "blocked",
            message: res.__("Ваш обліковий запис заблоковано на 5 хвилин."),
          });
        }

        return res.status(401).json({
          status: "invalid",
          errors: [{ error: "invalid", message: res.__("Невірний email або пароль.") }],
        });
      } else {
        // Успішна авторизація
        const id = results[0].id;
        const token = jwt.sign({ id: id }, jwtConfig.jwt.jwt_secret, {
          expiresIn: jwtConfig.jwt.jwt_time_expires,
        });

        const cookiesOptions = {
          expires: new Date(Date.now() + jwtConfig.jwt.jwt_cookie_expiring * 24 * 60 * 60 * 1000),
          httpOnly: true,
          secure: true,
        };

        // Встановлюємо термін дії cookie в залежності від опції remember_me
        if (remember_me) {
          cookiesOptions.expires = new Date(Date.now() + jwtConfig.jwt.jwt_cookie_expiring * 30 * 24 * 60 * 60 * 1000); // 30 днів
        } else {
          cookiesOptions.expires = new Date(Date.now() + jwtConfig.jwt.jwt_cookie_expiring * 24 * 60 * 60 * 1000); // 1 день
        }

        res.cookie("login", token, cookiesOptions);
        return res.status(200).json({
          status: "success",
        });
      }
    });
  } catch (error) {
    console.error(error); // Логування помилок
    return res.status(500).json({ status: "error", message: res.__("Внутрішня помилка сервера.") });
  }
};

/*exports.register = async (req, res) => {
    try {
        const first_name = req.body.first_name
        const last_name = req.body.last_name
        const email = req.body.email
        const city = req.body.city
        const country = req.body.country
        const gender = req.body.gender
        const password = req.body.password
        const confirm_password = req.body.confirm_password
        //let passwordHash = await bcryptjs.hash(password, 12)
        let passwordHash = await bcryptjs.hash(password, 8)
        let email_verification_token = "123"
        i18n.init(req, res)
        connection.query("INSERT INTO " + configDatabase.prefix + "users(first_name, last_name, email, active, secret_key, password) VALUES('" + first_name + "', '" + last_name + "', '" + email + "', '0', '" + email_verification_token + "', '" + passwordHash + "') ON DUPLICATE KEY UPDATE email='" + email + "'", (error, results, fields) => {
            if (error) {
                console.log(error)
            }
            if (results.insertId == "0") {
                var email_exists = [];

                var newLength = email_exists.push({ 'error': 'email_exists', 'msg': '123' });

                res.json({
                    status: "error",
                    errors: email_exists
                });
            } else {
                res.json({
                    status: "success",
                    email_verification_token: "" + email_verification_token + ""
                });
            }
            //res.redirect('/')
        });


    } catch (error) {
        console.log(error)
    }
}*/

// END Авторизація

// Деавторизація
exports.logout = async (req, res) => {
  try {
    res.clearCookie("login"); // Очищаємо cookie
    return res.redirect("/"); // Перенаправляємо користувача на головну сторінку
  } catch (error) {
    logging.error(error); // Якщо є помилка, записуємо її.
    return res.status(500).json({ message: "Internal Server Error" }); // Відправляємо відповідь з кодом помилки
  }
};
// END Деавторизація

// Cкинути пароль
exports.reset_password = async (req, res) => {
  try {
    const email = req.body.email;

    // Перевірка коректності email
    if (!validator.isEmail(email)) {
      return res.status(401).json({
        status: "error",
        errors: [
          {
            error: "email",
            msg: res.__("please_fill_out_this_field"),
          },
        ],
      });
    }

    // Перевіряємо, чи існує користувач з таким email
    connection.query("SELECT * FROM " + configDatabase.prefix + "users WHERE email = ?", [email], async (error, results) => {
      if (error) {
        console.log(error);
        return res.json({
          status: "error",
          msg: res.__("internal_server_error"),
        });
      }

      if (results.length === 0) {
        return res.json({
          status: "success",
        });
      }

      // Генеруємо токен для скидання пароля
      const token = crypto.randomBytes(32).toString("hex");
      const expireTime = new Date(Date.now() + 3600000 * 3)
        .toISOString() // Отримуємо строку у форматі ISO (YYYY-MM-DDTHH:MM:SS.sssZ)
        .slice(0, 19) // Відрізаємо зайві частини (мілісекунди та часову зону)
        .replace("T", " ");

      // Зберігаємо токен і час дії в базу даних
      connection.query("UPDATE " + configDatabase.prefix + "users SET reset_password_token = ?, reset_password_time = ? WHERE email = ?", [token, expireTime, email], async (error, results) => {
        if (error) {
          console.log(error);
        }

        res.json({
          status: "success",
        });
      });
    });
  } catch (error) {
    console.log(error);
    res.json({
      status: "error",
      msg: res.__("internal_server_error"),
    });
  }
};
// EMD Cкинути пароль
