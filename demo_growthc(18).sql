-- phpMyAdmin SQL Dump
-- version 5.2.3
-- https://www.phpmyadmin.net/
--
-- Хост: localhost
-- Час створення: Вер 05 2026 р., 04:46
-- Версія сервера: 8.0.46-0ubuntu0.22.04.4
-- Версія PHP: 7.4.33

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- База даних: `demo_growthc`
--

-- --------------------------------------------------------

--
-- Структура таблиці `8ydnb966_users`
--

CREATE TABLE `8ydnb966_users` (
  `id` int UNSIGNED NOT NULL,
  `email` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `password` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `first_name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT 'Ім''я',
  `last_name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT 'Прізвище',
  `patronymic` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT 'По-батькові',
  `phone` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `birthday` date DEFAULT NULL,
  `gender` tinyint UNSIGNED NOT NULL DEFAULT '0' COMMENT '0=не вказано 1=чоловік 2=жінка',
  `avatar` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT 'Назва файлу. Шлях: /uploads/users/{id}/{avatar}',
  `id_lang` smallint UNSIGNED NOT NULL DEFAULT '1',
  `active` tinyint UNSIGNED NOT NULL DEFAULT '0' COMMENT '0=неактивний 1=активний 2=заблокований 3=запрошений',
  `tfa_enabled` tinyint UNSIGNED NOT NULL DEFAULT '0',
  `tfa_secret` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `tfa_secret_pending` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `tfa_last_step` bigint UNSIGNED NOT NULL DEFAULT '0',
  `tfa_failed_attempts` tinyint UNSIGNED NOT NULL DEFAULT '0',
  `tfa_locked_until` datetime DEFAULT NULL,
  `reset_token` varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `reset_token_expires` datetime DEFAULT NULL,
  `failed_login_attempts` tinyint UNSIGNED NOT NULL DEFAULT '0',
  `locked_until` datetime DEFAULT NULL,
  `token_version` int UNSIGNED NOT NULL DEFAULT '0',
  `id_created_by` int UNSIGNED DEFAULT NULL COMMENT 'NULL = зареєструвався сам',
  `date_last_login` datetime DEFAULT NULL,
  `date_online_since` datetime DEFAULT NULL COMMENT 'Коли юзер став онлайн (перша вкладка)',
  `date_last_seen` datetime DEFAULT NULL COMMENT 'Коли юзер востаннє був онлайн',
  `date_add` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `date_edit` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Дамп даних таблиці `8ydnb966_users`
--

INSERT INTO `8ydnb966_users` (`id`, `email`, `password`, `first_name`, `last_name`, `patronymic`, `phone`, `birthday`, `gender`, `avatar`, `id_lang`, `active`, `tfa_enabled`, `tfa_secret`, `tfa_secret_pending`, `tfa_last_step`, `tfa_failed_attempts`, `tfa_locked_until`, `reset_token`, `reset_token_expires`, `failed_login_attempts`, `locked_until`, `token_version`, `id_created_by`, `date_last_login`, `date_online_since`, `date_last_seen`, `date_add`, `date_edit`) VALUES
(1, 'motchanyy@gmail.com', '$2a$12$h6C/KZLMoByyPYu5Y6bane/hwl9mi2XnoNjTyWi6/g4weyv/Gt746', 'Сергій', 'Мотчаний', 'Сергійович', '', NULL, 1, NULL, 2, 1, 0, '', '', 0, 0, NULL, NULL, NULL, 0, NULL, 12, NULL, '2026-09-03 12:41:14', NULL, '2026-09-03 13:26:41', '2026-03-26 18:20:52', '2026-09-03 13:26:41');

-- --------------------------------------------------------

--
-- Структура таблиці `8ydnb966_users_groups`
--

CREATE TABLE `8ydnb966_users_groups` (
  `id` smallint UNSIGNED NOT NULL,
  `active` tinyint UNSIGNED NOT NULL DEFAULT '1',
  `id_created_by` int UNSIGNED DEFAULT NULL COMMENT 'NULL = система',
  `date_add` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `date_edit` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Дамп даних таблиці `8ydnb966_users_groups`
--

INSERT INTO `8ydnb966_users_groups` (`id`, `active`, `id_created_by`, `date_add`, `date_edit`) VALUES
(1, 1, NULL, '2026-03-26 17:16:57', '2026-03-26 17:16:57'),
(2, 1, NULL, '2026-03-26 17:16:57', '2026-03-26 17:16:57');

-- --------------------------------------------------------

--
-- Структура таблиці `8ydnb966_users_groups_lang`
--

CREATE TABLE `8ydnb966_users_groups_lang` (
  `id` int UNSIGNED NOT NULL,
  `id_group` smallint UNSIGNED NOT NULL,
  `id_lang` smallint UNSIGNED NOT NULL,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `note` varchar(500) COLLATE utf8mb4_unicode_ci DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Дамп даних таблиці `8ydnb966_users_groups_lang`
--

INSERT INTO `8ydnb966_users_groups_lang` (`id`, `id_group`, `id_lang`, `name`, `note`) VALUES
(1, 1, 1, 'Адміністратор', NULL),
(2, 1, 2, 'Administrator', NULL),
(3, 2, 1, 'Менеджер', NULL),
(4, 2, 2, 'Manager', NULL);

-- --------------------------------------------------------

--
-- Структура таблиці `8ydnb966_users_groups_permissions`
--

CREATE TABLE `8ydnb966_users_groups_permissions` (
  `id_group` smallint UNSIGNED NOT NULL,
  `id_page` smallint UNSIGNED NOT NULL,
  `can_view` tinyint UNSIGNED NOT NULL DEFAULT '0',
  `can_add` tinyint UNSIGNED NOT NULL DEFAULT '0',
  `can_edit` tinyint UNSIGNED NOT NULL DEFAULT '0',
  `can_delete` tinyint UNSIGNED NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Дамп даних таблиці `8ydnb966_users_groups_permissions`
--

INSERT INTO `8ydnb966_users_groups_permissions` (`id_group`, `id_page`, `can_view`, `can_add`, `can_edit`, `can_delete`) VALUES
(1, 10, 1, 1, 1, 1),
(1, 11, 1, 1, 1, 1),
(1, 12, 1, 1, 1, 1),
(1, 90, 1, 1, 1, 1),
(1, 91, 1, 1, 1, 1),
(2, 10, 1, 1, 1, 1),
(2, 11, 1, 1, 1, 1),
(2, 12, 1, 1, 1, 1),
(2, 90, 1, 1, 1, 1),
(2, 91, 1, 1, 1, 1);

-- --------------------------------------------------------

--
-- Структура таблиці `8ydnb966_users_invites`
--

CREATE TABLE `8ydnb966_users_invites` (
  `id` int UNSIGNED NOT NULL,
  `email` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `token` varchar(128) COLLATE utf8mb4_unicode_ci NOT NULL,
  `id_group` smallint UNSIGNED DEFAULT NULL COMMENT 'Група після реєстрації',
  `id_created_by` int UNSIGNED NOT NULL COMMENT 'Хто запросив',
  `status` tinyint UNSIGNED NOT NULL DEFAULT '0' COMMENT '0=очікує 1=завершено',
  `expires_at` datetime NOT NULL,
  `date_accepted` datetime DEFAULT NULL COMMENT 'Дата завершення реєстрації',
  `date_add` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `date_edit` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Структура таблиці `8ydnb966_users_login_log`
--

CREATE TABLE `8ydnb966_users_login_log` (
  `id` bigint UNSIGNED NOT NULL,
  `id_user` int UNSIGNED NOT NULL,
  `ip` varchar(45) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT 'IPv4 або IPv6',
  `country` varchar(2) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT 'Код країни: UA, PL...',
  `city` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `user_agent` varchar(512) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `device` tinyint UNSIGNED NOT NULL DEFAULT '0' COMMENT '0=desktop 1=mobile 2=tablet',
  `status` tinyint UNSIGNED NOT NULL DEFAULT '0' COMMENT '0=невдала 1=успішна',
  `date_add` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
PARTITION BY RANGE (((year(`date_add`) * 100) + month(`date_add`)))
(
PARTITION p202601 VALUES LESS THAN (202602) ENGINE=InnoDB,
PARTITION p202602 VALUES LESS THAN (202603) ENGINE=InnoDB,
PARTITION p202603 VALUES LESS THAN (202604) ENGINE=InnoDB,
PARTITION p202604 VALUES LESS THAN (202605) ENGINE=InnoDB,
PARTITION p202605 VALUES LESS THAN (202606) ENGINE=InnoDB,
PARTITION p202606 VALUES LESS THAN (202607) ENGINE=InnoDB,
PARTITION p202607 VALUES LESS THAN (202608) ENGINE=InnoDB,
PARTITION p202608 VALUES LESS THAN (202609) ENGINE=InnoDB,
PARTITION p202609 VALUES LESS THAN (202610) ENGINE=InnoDB,
PARTITION p202610 VALUES LESS THAN (202611) ENGINE=InnoDB,
PARTITION p202611 VALUES LESS THAN (202612) ENGINE=InnoDB,
PARTITION p202612 VALUES LESS THAN (202613) ENGINE=InnoDB,
PARTITION pmax VALUES LESS THAN MAXVALUE ENGINE=InnoDB
);

--
-- Дамп даних таблиці `8ydnb966_users_login_log`
--

INSERT INTO `8ydnb966_users_login_log` (`id`, `id_user`, `ip`, `country`, `city`, `user_agent`, `device`, `status`, `date_add`) VALUES
(24, 17, '::ffff:127.0.0.1', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0', 0, 1, '2026-03-27 16:48:00'),
(26, 17, '::ffff:127.0.0.1', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0', 0, 1, '2026-03-27 16:52:37'),
(27, 17, '::ffff:127.0.0.1', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0', 0, 1, '2026-03-27 16:52:46'),
(29, 17, '::1', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36', 0, 1, '2026-03-27 17:05:20'),
(30, 17, '::1', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36', 0, 1, '2026-03-27 18:53:59'),
(37, 17, '::ffff:127.0.0.1', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0', 0, 0, '2026-05-21 23:19:22'),
(38, 17, '::ffff:127.0.0.1', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0', 0, 0, '2026-05-21 23:19:25'),
(39, 17, '::ffff:127.0.0.1', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0', 0, 0, '2026-05-21 23:19:29'),
(74, 1, '134.249.10.162', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0', 0, 1, '2026-08-14 04:55:07'),
(75, 1, '134.249.10.162', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0', 0, 1, '2026-08-14 13:20:18'),
(76, 1, '134.249.10.162', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0', 0, 1, '2026-08-14 13:20:35'),
(77, 1, '::ffff:127.0.0.1', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0', 0, 1, '2026-08-14 14:22:17'),
(78, 1, '134.249.10.162', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0', 0, 1, '2026-08-16 03:57:23'),
(79, 1, '::ffff:127.0.0.1', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0', 0, 1, '2026-08-18 18:45:08'),
(80, 1, '::ffff:127.0.0.1', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:154.0) Gecko/20100101 Firefox/154.0', 0, 1, '2026-08-21 15:55:11'),
(81, 1, '::ffff:127.0.0.1', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:154.0) Gecko/20100101 Firefox/154.0', 0, 0, '2026-08-21 15:56:13'),
(82, 1, '::ffff:127.0.0.1', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:154.0) Gecko/20100101 Firefox/154.0', 0, 1, '2026-08-21 15:56:27'),
(83, 1, '188.163.14.150', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:154.0) Gecko/20100101 Firefox/154.0', 0, 1, '2026-08-22 01:45:58'),
(84, 1, '188.163.14.150', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:154.0) Gecko/20100101 Firefox/154.0', 0, 1, '2026-08-23 20:55:58'),
(85, 1, '::ffff:127.0.0.1', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:154.0) Gecko/20100101 Firefox/154.0', 0, 1, '2026-08-26 04:52:30'),
(86, 1, '188.163.14.150', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:154.0) Gecko/20100101 Firefox/154.0', 0, 1, '2026-08-30 22:52:20'),
(87, 1, '188.163.14.150', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:154.0) Gecko/20100101 Firefox/154.0', 0, 1, '2026-08-31 16:39:39'),
(88, 1, '185.155.90.98', '', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6 Mobile/15E148 Safari/604.1', 1, 1, '2026-08-31 16:42:50'),
(89, 1, '188.163.14.150', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:154.0) Gecko/20100101 Firefox/154.0', 0, 1, '2026-08-31 18:04:41'),
(90, 1, '::ffff:127.0.0.1', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:154.0) Gecko/20100101 Firefox/154.0', 0, 1, '2026-08-31 18:16:44'),
(91, 1, '::ffff:127.0.0.1', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:154.0) Gecko/20100101 Firefox/154.0', 0, 1, '2026-09-01 00:47:46'),
(92, 1, '188.163.14.150', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:154.0) Gecko/20100101 Firefox/154.0', 0, 1, '2026-09-01 04:16:27'),
(93, 1, '188.163.14.150', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0', 0, 1, '2026-09-02 21:44:07'),
(94, 1, '62.80.189.252', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36', 0, 1, '2026-09-03 12:27:33'),
(95, 1, '62.80.189.252', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36', 0, 1, '2026-09-03 12:27:58'),
(96, 1, '62.80.189.252', '', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36', 0, 1, '2026-09-03 12:36:29');

-- --------------------------------------------------------

--
-- Структура таблиці `8ydnb966_users_permissions_pages`
--

CREATE TABLE `8ydnb966_users_permissions_pages` (
  `id` smallint UNSIGNED NOT NULL,
  `slug` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Унікальний ключ: users.list, products.catalog',
  `parent_id` smallint UNSIGNED DEFAULT NULL COMMENT 'NULL = корінь дерева',
  `sort_order` smallint UNSIGNED NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Дамп даних таблиці `8ydnb966_users_permissions_pages`
--

INSERT INTO `8ydnb966_users_permissions_pages` (`id`, `slug`, `parent_id`, `sort_order`) VALUES
(1, 'users', NULL, 10),
(2, 'settings', NULL, 90),
(10, 'users.list', 1, 10),
(11, 'users.groups', 1, 20),
(12, 'users.invites', 1, 30),
(90, 'settings.general', 2, 10),
(91, 'settings.languages', 2, 20);

-- --------------------------------------------------------

--
-- Структура таблиці `8ydnb966_users_permissions_pages_lang`
--

CREATE TABLE `8ydnb966_users_permissions_pages_lang` (
  `id` int UNSIGNED NOT NULL,
  `id_page` smallint UNSIGNED NOT NULL,
  `id_lang` smallint UNSIGNED NOT NULL,
  `name` varchar(150) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Дамп даних таблиці `8ydnb966_users_permissions_pages_lang`
--

INSERT INTO `8ydnb966_users_permissions_pages_lang` (`id`, `id_page`, `id_lang`, `name`) VALUES
(1, 1, 1, 'Користувачі'),
(2, 1, 2, 'Users'),
(3, 2, 1, 'Налаштування'),
(4, 2, 2, 'Settings'),
(5, 10, 1, 'Список користувачів'),
(6, 10, 2, 'User list'),
(7, 11, 1, 'Групи'),
(8, 11, 2, 'Groups'),
(9, 12, 1, 'Запрошення'),
(10, 12, 2, 'Invites'),
(11, 90, 1, 'Загальні'),
(12, 90, 2, 'General'),
(13, 91, 1, 'Мови'),
(14, 91, 2, 'Languages');

-- --------------------------------------------------------

--
-- Структура таблиці `8ydnb966_users_tfa_backup_codes`
--

CREATE TABLE `8ydnb966_users_tfa_backup_codes` (
  `id` bigint UNSIGNED NOT NULL,
  `id_user` int UNSIGNED NOT NULL,
  `code_hash` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `used_at` datetime DEFAULT NULL,
  `date_add` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Структура таблиці `8ydnb966_users_to_groups`
--

CREATE TABLE `8ydnb966_users_to_groups` (
  `id_user` int UNSIGNED NOT NULL,
  `id_group` smallint UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Дамп даних таблиці `8ydnb966_users_to_groups`
--

INSERT INTO `8ydnb966_users_to_groups` (`id_user`, `id_group`) VALUES
(1, 1);

-- --------------------------------------------------------

--
-- Структура таблиці `8ydnb966_users_ui_settings`
--

CREATE TABLE `8ydnb966_users_ui_settings` (
  `id` int UNSIGNED NOT NULL,
  `id_user` int UNSIGNED NOT NULL,
  `key` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `value` json NOT NULL,
  `date_add` datetime NOT NULL,
  `date_edit` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Індекси збережених таблиць
--

--
-- Індекси таблиці `8ydnb966_users`
--
ALTER TABLE `8ydnb966_users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_email` (`email`),
  ADD KEY `idx_active` (`active`),
  ADD KEY `idx_id_lang` (`id_lang`),
  ADD KEY `idx_id_created_by` (`id_created_by`),
  ADD KEY `idx_last_name` (`last_name`),
  ADD KEY `idx_first_name` (`first_name`);

--
-- Індекси таблиці `8ydnb966_users_groups`
--
ALTER TABLE `8ydnb966_users_groups`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_active` (`active`),
  ADD KEY `idx_id_created_by` (`id_created_by`);

--
-- Індекси таблиці `8ydnb966_users_groups_lang`
--
ALTER TABLE `8ydnb966_users_groups_lang`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_group_lang` (`id_group`,`id_lang`),
  ADD KEY `idx_id_group` (`id_group`),
  ADD KEY `fk_groups_lang_lang` (`id_lang`);

--
-- Індекси таблиці `8ydnb966_users_groups_permissions`
--
ALTER TABLE `8ydnb966_users_groups_permissions`
  ADD PRIMARY KEY (`id_group`,`id_page`),
  ADD KEY `idx_id_page` (`id_page`);

--
-- Індекси таблиці `8ydnb966_users_invites`
--
ALTER TABLE `8ydnb966_users_invites`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_token` (`token`),
  ADD UNIQUE KEY `uq_email` (`email`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_expires_at` (`expires_at`),
  ADD KEY `idx_id_created_by` (`id_created_by`);

--
-- Індекси таблиці `8ydnb966_users_login_log`
--
ALTER TABLE `8ydnb966_users_login_log`
  ADD PRIMARY KEY (`id`,`date_add`),
  ADD KEY `idx_id_user` (`id_user`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_id_user_date_add` (`id_user`,`date_add`);

--
-- Індекси таблиці `8ydnb966_users_permissions_pages`
--
ALTER TABLE `8ydnb966_users_permissions_pages`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_slug` (`slug`),
  ADD KEY `idx_parent` (`parent_id`);

--
-- Індекси таблиці `8ydnb966_users_permissions_pages_lang`
--
ALTER TABLE `8ydnb966_users_permissions_pages_lang`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_page_lang` (`id_page`,`id_lang`),
  ADD KEY `idx_id_lang` (`id_lang`);

--
-- Індекси таблиці `8ydnb966_users_tfa_backup_codes`
--
ALTER TABLE `8ydnb966_users_tfa_backup_codes`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_user_unused` (`id_user`,`used_at`);

--
-- Індекси таблиці `8ydnb966_users_to_groups`
--
ALTER TABLE `8ydnb966_users_to_groups`
  ADD PRIMARY KEY (`id_user`,`id_group`),
  ADD KEY `idx_id_group` (`id_group`);

--
-- Індекси таблиці `8ydnb966_users_ui_settings`
--
ALTER TABLE `8ydnb966_users_ui_settings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_user_key` (`id_user`,`key`);

--
-- AUTO_INCREMENT для збережених таблиць
--

--
-- AUTO_INCREMENT для таблиці `8ydnb966_users`
--
ALTER TABLE `8ydnb966_users`
  MODIFY `id` int UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=19;

--
-- AUTO_INCREMENT для таблиці `8ydnb966_users_groups`
--
ALTER TABLE `8ydnb966_users_groups`
  MODIFY `id` smallint UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT для таблиці `8ydnb966_users_groups_lang`
--
ALTER TABLE `8ydnb966_users_groups_lang`
  MODIFY `id` int UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT для таблиці `8ydnb966_users_invites`
--
ALTER TABLE `8ydnb966_users_invites`
  MODIFY `id` int UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT для таблиці `8ydnb966_users_login_log`
--
ALTER TABLE `8ydnb966_users_login_log`
  MODIFY `id` bigint UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=97;

--
-- AUTO_INCREMENT для таблиці `8ydnb966_users_permissions_pages`
--
ALTER TABLE `8ydnb966_users_permissions_pages`
  MODIFY `id` smallint UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=92;

--
-- AUTO_INCREMENT для таблиці `8ydnb966_users_permissions_pages_lang`
--
ALTER TABLE `8ydnb966_users_permissions_pages_lang`
  MODIFY `id` int UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=15;

--
-- AUTO_INCREMENT для таблиці `8ydnb966_users_tfa_backup_codes`
--
ALTER TABLE `8ydnb966_users_tfa_backup_codes`
  MODIFY `id` bigint UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT для таблиці `8ydnb966_users_ui_settings`
--
ALTER TABLE `8ydnb966_users_ui_settings`
  MODIFY `id` int UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- Обмеження зовнішнього ключа збережених таблиць
--

--
-- Обмеження зовнішнього ключа таблиці `8ydnb966_users`
--
ALTER TABLE `8ydnb966_users`
  ADD CONSTRAINT `fk_users_created_by` FOREIGN KEY (`id_created_by`) REFERENCES `8ydnb966_users` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_users_lang` FOREIGN KEY (`id_lang`) REFERENCES `8ydnb966_languages` (`id`);

--
-- Обмеження зовнішнього ключа таблиці `8ydnb966_users_groups`
--
ALTER TABLE `8ydnb966_users_groups`
  ADD CONSTRAINT `fk_groups_created_by` FOREIGN KEY (`id_created_by`) REFERENCES `8ydnb966_users` (`id`) ON DELETE SET NULL;

--
-- Обмеження зовнішнього ключа таблиці `8ydnb966_users_groups_lang`
--
ALTER TABLE `8ydnb966_users_groups_lang`
  ADD CONSTRAINT `fk_groups_lang_group` FOREIGN KEY (`id_group`) REFERENCES `8ydnb966_users_groups` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_groups_lang_lang` FOREIGN KEY (`id_lang`) REFERENCES `8ydnb966_languages` (`id`);

--
-- Обмеження зовнішнього ключа таблиці `8ydnb966_users_groups_permissions`
--
ALTER TABLE `8ydnb966_users_groups_permissions`
  ADD CONSTRAINT `fk_ugp_group` FOREIGN KEY (`id_group`) REFERENCES `8ydnb966_users_groups` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_ugp_page` FOREIGN KEY (`id_page`) REFERENCES `8ydnb966_users_permissions_pages` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Обмеження зовнішнього ключа таблиці `8ydnb966_users_invites`
--
ALTER TABLE `8ydnb966_users_invites`
  ADD CONSTRAINT `fk_invites_created_by` FOREIGN KEY (`id_created_by`) REFERENCES `8ydnb966_users` (`id`) ON DELETE CASCADE;

--
-- Обмеження зовнішнього ключа таблиці `8ydnb966_users_permissions_pages_lang`
--
ALTER TABLE `8ydnb966_users_permissions_pages_lang`
  ADD CONSTRAINT `fk_uppl_page` FOREIGN KEY (`id_page`) REFERENCES `8ydnb966_users_permissions_pages` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Обмеження зовнішнього ключа таблиці `8ydnb966_users_tfa_backup_codes`
--
ALTER TABLE `8ydnb966_users_tfa_backup_codes`
  ADD CONSTRAINT `fk_tfa_bc_user` FOREIGN KEY (`id_user`) REFERENCES `8ydnb966_users` (`id`) ON DELETE CASCADE;

--
-- Обмеження зовнішнього ключа таблиці `8ydnb966_users_to_groups`
--
ALTER TABLE `8ydnb966_users_to_groups`
  ADD CONSTRAINT `fk_utg_group` FOREIGN KEY (`id_group`) REFERENCES `8ydnb966_users_groups` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_utg_user` FOREIGN KEY (`id_user`) REFERENCES `8ydnb966_users` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
