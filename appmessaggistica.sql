-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Creato il: Apr 07, 2026 alle 16:19
-- Versione del server: 10.4.32-MariaDB
-- Versione PHP: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `appmessaggistica`
--

-- --------------------------------------------------------

--
-- Struttura della tabella `chats`
--

CREATE TABLE `chats` (
  `id` bigint(20) NOT NULL,
  `name` varchar(100) DEFAULT NULL,
  `counter` bigint(20) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Struttura della tabella `chats_nonces_logs`
--

CREATE TABLE `chats_nonces_logs` (
  `id_chat` bigint(20) NOT NULL,
  `nonce` binary(24) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Struttura della tabella `contacts`
--

CREATE TABLE `contacts` (
  `id_user` bigint(20) NOT NULL,
  `username_hash` binary(32) NOT NULL,
  `username_contact` varchar(197) NOT NULL,
  `username_nonce` binary(24) NOT NULL,
  `nickname` varchar(100) NOT NULL,
  `nickname_nonce` binary(24) NOT NULL,
  `is_blocked` tinyint(1) NOT NULL DEFAULT 0,
  `key_flag` tinyint(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Struttura della tabella `errors_logs`
--

CREATE TABLE `errors_logs` (
  `id` bigint(20) NOT NULL,
  `log` mediumtext DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Struttura della tabella `members_chat`
--

CREATE TABLE `members_chat` (
  `id_user` bigint(20) NOT NULL,
  `id_chat` bigint(20) NOT NULL,
  `id_msg_bgn` bigint(20) DEFAULT NULL,
  `chat_key` varchar(130) NOT NULL,
  `chat_key_nonce` binary(24) NOT NULL,
  `last_msg_read_id` bigint(20) NOT NULL DEFAULT 0,
  `key_flag` tinyint(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Struttura della tabella `messages`
--

CREATE TABLE `messages` (
  `id` bigint(20) NOT NULL,
  `id_chat` bigint(20) NOT NULL,
  `id_sender` bigint(20) NOT NULL,
  `message` varbinary(4000) NOT NULL,
  `message_nonce` binary(24) NOT NULL,
  `send_time` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Struttura della tabella `removed_messages`
--

CREATE TABLE `removed_messages` (
  `id_user` bigint(20) NOT NULL,
  `id_chat` binary(8) NOT NULL,
  `id_chat_nonce` binary(24) NOT NULL,
  `id_msg` binary(8) NOT NULL,
  `id_msg_nonce` binary(24) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Struttura della tabella `users`
--

CREATE TABLE `users` (
  `id` bigint(20) NOT NULL,
  `username` varchar(100) NOT NULL,
  `last_log` datetime DEFAULT NULL,
  `pwd_hash` binary(32) NOT NULL,
  `pwd_salt` binary(16) NOT NULL,
  `cipher_mk` binary(48) NOT NULL,
  `mk_nonce` binary(8) NOT NULL,
  `recovery_mk` binary(32) NOT NULL,
  `pub_key` binary(33) NOT NULL,
  `failed_logins` tinyint(3) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Struttura della tabella `users_nonces_logs`
--

CREATE TABLE `users_nonces_logs` (
  `id_user` bigint(20) NOT NULL,
  `nonce` binary(24) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Indici per le tabelle scaricate
--

--
-- Indici per le tabelle `chats`
--
ALTER TABLE `chats`
  ADD PRIMARY KEY (`id`);

--
-- Indici per le tabelle `chats_nonces_logs`
--
ALTER TABLE `chats_nonces_logs`
  ADD PRIMARY KEY (`id_chat`,`nonce`);

--
-- Indici per le tabelle `contacts`
--
ALTER TABLE `contacts`
  ADD PRIMARY KEY (`id_user`,`username_hash`);

--
-- Indici per le tabelle `errors_logs`
--
ALTER TABLE `errors_logs`
  ADD PRIMARY KEY (`id`);

--
-- Indici per le tabelle `members_chat`
--
ALTER TABLE `members_chat`
  ADD PRIMARY KEY (`id_user`,`id_chat`),
  ADD KEY `fk_mc_chat` (`id_chat`);

--
-- Indici per le tabelle `messages`
--
ALTER TABLE `messages`
  ADD PRIMARY KEY (`id`),
  ADD KEY `messages_id_user` (`id_chat`,`id_sender`),
  ADD KEY `fk_msg_sender` (`id_sender`);

--
-- Indici per le tabelle `removed_messages`
--
ALTER TABLE `removed_messages`
  ADD PRIMARY KEY (`id_user`,`id_chat`,`id_msg`);

--
-- Indici per le tabelle `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- Indici per le tabelle `users_nonces_logs`
--
ALTER TABLE `users_nonces_logs`
  ADD PRIMARY KEY (`id_user`,`nonce`);

--
-- AUTO_INCREMENT per le tabelle scaricate
--

--
-- AUTO_INCREMENT per la tabella `chats`
--
ALTER TABLE `chats`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT per la tabella `errors_logs`
--
ALTER TABLE `errors_logs`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT per la tabella `messages`
--
ALTER TABLE `messages`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT per la tabella `users`
--
ALTER TABLE `users`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT;

--
-- Limiti per le tabelle scaricate
--

--
-- Limiti per la tabella `chats_nonces_logs`
--
ALTER TABLE `chats_nonces_logs`
  ADD CONSTRAINT `fk_cnl_chat` FOREIGN KEY (`id_chat`) REFERENCES `chats` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Limiti per la tabella `contacts`
--
ALTER TABLE `contacts`
  ADD CONSTRAINT `fk_contacts_user` FOREIGN KEY (`id_user`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Limiti per la tabella `members_chat`
--
ALTER TABLE `members_chat`
  ADD CONSTRAINT `fk_mc_chat` FOREIGN KEY (`id_chat`) REFERENCES `chats` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_mc_user` FOREIGN KEY (`id_user`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Limiti per la tabella `messages`
--
ALTER TABLE `messages`
  ADD CONSTRAINT `fk_msg_chat` FOREIGN KEY (`id_chat`) REFERENCES `chats` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_msg_sender` FOREIGN KEY (`id_sender`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Limiti per la tabella `removed_messages`
--
ALTER TABLE `removed_messages`
  ADD CONSTRAINT `fk_rm_user` FOREIGN KEY (`id_user`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Limiti per la tabella `users_nonces_logs`
--
ALTER TABLE `users_nonces_logs`
  ADD CONSTRAINT `fk_unl_user` FOREIGN KEY (`id_user`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
