-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Creato il: Dic 22, 2025 alle 14:22
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
  `id` bigint(20) UNSIGNED NOT NULL,
  `name` varbinary(100) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Struttura della tabella `contacts`
--

CREATE TABLE `contacts` (
  `id_user` bigint(20) UNSIGNED NOT NULL,
  `id_contact` binary(8) NOT NULL,
  `nickname_contact` varbinary(100) NOT NULL,
  `is_blocked` tinyint(1) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Struttura della tabella `members_chat`
--

CREATE TABLE `members_chat` (
  `id_user` bigint(20) UNSIGNED NOT NULL,
  `id_chat` binary(8) NOT NULL,
  `id_msg_start` binary(8) NOT NULL,
  `chat_key` binary(16) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Struttura della tabella `messages`
--

CREATE TABLE `messages` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `id_chat` binary(8) NOT NULL,
  `id_sender` bigint(20) UNSIGNED DEFAULT NULL,
  `message` varbinary(4000) NOT NULL,
  `send_time` binary(5) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Struttura della tabella `removed_messages`
--

CREATE TABLE `removed_messages` (
  `id_user` bigint(20) UNSIGNED NOT NULL,
  `id_chat` binary(8) NOT NULL,
  `id_msg` binary(8) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Struttura della tabella `users`
--

CREATE TABLE `users` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `username` varchar(25) DEFAULT NULL,
  `password_hash` binary(60) NOT NULL,
  `public_key` binary(33) NOT NULL,
  `failed_logins` tinyint(3) UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dump dei dati per la tabella `users`
--

INSERT INTO `users` (`id`, `username`, `password_hash`, `public_key`, `failed_logins`) VALUES
(2, 'Giuseppe', 0x243261243130244b46774f5351696e4a497a3947633633704f4c32337565506655475939486a4a52303733706f4c505a6e30324b546c315a6558674b, 0x02195d48353d097bf592a3819b8275cccab276a34ff4e483918426cfb878a0bbef, 0);

--
-- Indici per le tabelle scaricate
--

--
-- Indici per le tabelle `chats`
--
ALTER TABLE `chats`
  ADD PRIMARY KEY (`id`);

--
-- Indici per le tabelle `contacts`
--
ALTER TABLE `contacts`
  ADD PRIMARY KEY (`id_user`,`id_contact`);

--
-- Indici per le tabelle `members_chat`
--
ALTER TABLE `members_chat`
  ADD PRIMARY KEY (`id_user`,`id_chat`);

--
-- Indici per le tabelle `messages`
--
ALTER TABLE `messages`
  ADD PRIMARY KEY (`id`,`id_chat`),
  ADD KEY `messages_id_user` (`id_sender`);

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
-- AUTO_INCREMENT per le tabelle scaricate
--

--
-- AUTO_INCREMENT per la tabella `chats`
--
ALTER TABLE `chats`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT per la tabella `users`
--
ALTER TABLE `users`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- Limiti per le tabelle scaricate
--

--
-- Limiti per la tabella `contacts`
--
ALTER TABLE `contacts`
  ADD CONSTRAINT `contacts_id_user` FOREIGN KEY (`id_user`) REFERENCES `users` (`id`);

--
-- Limiti per la tabella `members_chat`
--
ALTER TABLE `members_chat`
  ADD CONSTRAINT `members_id_user` FOREIGN KEY (`id_user`) REFERENCES `users` (`id`);

--
-- Limiti per la tabella `messages`
--
ALTER TABLE `messages`
  ADD CONSTRAINT `messages_id_user` FOREIGN KEY (`id_sender`) REFERENCES `users` (`id`);

--
-- Limiti per la tabella `removed_messages`
--
ALTER TABLE `removed_messages`
  ADD CONSTRAINT `removed_messages_id_user` FOREIGN KEY (`id_user`) REFERENCES `users` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
