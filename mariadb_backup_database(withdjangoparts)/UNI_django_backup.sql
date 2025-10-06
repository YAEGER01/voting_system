/*M!999999\- enable the sandbox mode */ 
-- MariaDB dump 10.19-11.6.2-MariaDB, for Win64 (AMD64)
--
-- Host: localhost    Database: UNI_django
-- ------------------------------------------------------
-- Server version	11.6.2-MariaDB

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*M!100616 SET @OLD_NOTE_VERBOSITY=@@NOTE_VERBOSITY, NOTE_VERBOSITY=0 */;

--
-- Table structure for table `auth_group`
--

DROP TABLE IF EXISTS `auth_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_group` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(150) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_group`
--

LOCK TABLES `auth_group` WRITE;
/*!40000 ALTER TABLE `auth_group` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_group` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_group_permissions`
--

DROP TABLE IF EXISTS `auth_group_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_group_permissions` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `group_id` int(11) NOT NULL,
  `permission_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_group_permissions_group_id_permission_id_0cd325b0_uniq` (`group_id`,`permission_id`),
  KEY `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` (`permission_id`),
  CONSTRAINT `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  CONSTRAINT `auth_group_permissions_group_id_b120cbf9_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_group_permissions`
--

LOCK TABLES `auth_group_permissions` WRITE;
/*!40000 ALTER TABLE `auth_group_permissions` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_group_permissions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_permission`
--

DROP TABLE IF EXISTS `auth_permission`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_permission` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `content_type_id` int(11) NOT NULL,
  `codename` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_permission_content_type_id_codename_01ab375a_uniq` (`content_type_id`,`codename`),
  CONSTRAINT `auth_permission_content_type_id_2f476e4b_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=77 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_permission`
--

LOCK TABLES `auth_permission` WRITE;
/*!40000 ALTER TABLE `auth_permission` DISABLE KEYS */;
INSERT INTO `auth_permission` VALUES
(1,'Can add log entry',1,'add_logentry'),
(2,'Can change log entry',1,'change_logentry'),
(3,'Can delete log entry',1,'delete_logentry'),
(4,'Can view log entry',1,'view_logentry'),
(5,'Can add permission',2,'add_permission'),
(6,'Can change permission',2,'change_permission'),
(7,'Can delete permission',2,'delete_permission'),
(8,'Can view permission',2,'view_permission'),
(9,'Can add group',3,'add_group'),
(10,'Can change group',3,'change_group'),
(11,'Can delete group',3,'delete_group'),
(12,'Can view group',3,'view_group'),
(13,'Can add user',4,'add_user'),
(14,'Can change user',4,'change_user'),
(15,'Can delete user',4,'delete_user'),
(16,'Can view user',4,'view_user'),
(17,'Can add content type',5,'add_contenttype'),
(18,'Can change content type',5,'change_contenttype'),
(19,'Can delete content type',5,'delete_contenttype'),
(20,'Can view content type',5,'view_contenttype'),
(21,'Can add session',6,'add_session'),
(22,'Can change session',6,'change_session'),
(23,'Can delete session',6,'delete_session'),
(24,'Can view session',6,'view_session'),
(25,'Can add classroom position',7,'add_classroomposition'),
(26,'Can change classroom position',7,'change_classroomposition'),
(27,'Can delete classroom position',7,'delete_classroomposition'),
(28,'Can view classroom position',7,'view_classroomposition'),
(29,'Can add classroom settings',8,'add_classroomsettings'),
(30,'Can change classroom settings',8,'change_classroomsettings'),
(31,'Can delete classroom settings',8,'delete_classroomsettings'),
(32,'Can view classroom settings',8,'view_classroomsettings'),
(33,'Can add dashboard status',9,'add_dashboardstatus'),
(34,'Can change dashboard status',9,'change_dashboardstatus'),
(35,'Can delete dashboard status',9,'delete_dashboardstatus'),
(36,'Can view dashboard status',9,'view_dashboardstatus'),
(37,'Can add global settings',10,'add_globalsettings'),
(38,'Can change global settings',10,'change_globalsettings'),
(39,'Can delete global settings',10,'delete_globalsettings'),
(40,'Can view global settings',10,'view_globalsettings'),
(41,'Can add pending user',11,'add_pendinguser'),
(42,'Can change pending user',11,'change_pendinguser'),
(43,'Can delete pending user',11,'delete_pendinguser'),
(44,'Can view pending user',11,'view_pendinguser'),
(45,'Can add position',12,'add_position'),
(46,'Can change position',12,'change_position'),
(47,'Can delete position',12,'delete_position'),
(48,'Can view position',12,'view_position'),
(49,'Can add settings',13,'add_settings'),
(50,'Can change settings',13,'change_settings'),
(51,'Can delete settings',13,'delete_settings'),
(52,'Can view settings',13,'view_settings'),
(53,'Can add user',14,'add_user'),
(54,'Can change user',14,'change_user'),
(55,'Can delete user',14,'delete_user'),
(56,'Can view user',14,'view_user'),
(57,'Can add classroom votes',15,'add_classroomvotes'),
(58,'Can change classroom votes',15,'change_classroomvotes'),
(59,'Can delete classroom votes',15,'delete_classroomvotes'),
(60,'Can view classroom votes',15,'view_classroomvotes'),
(61,'Can add candidate',16,'add_candidate'),
(62,'Can change candidate',16,'change_candidate'),
(63,'Can delete candidate',16,'delete_candidate'),
(64,'Can view candidate',16,'view_candidate'),
(65,'Can add receipt access logs',17,'add_receiptaccesslogs'),
(66,'Can change receipt access logs',17,'change_receiptaccesslogs'),
(67,'Can delete receipt access logs',17,'delete_receiptaccesslogs'),
(68,'Can view receipt access logs',17,'view_receiptaccesslogs'),
(69,'Can add log',18,'add_log'),
(70,'Can change log',18,'change_log'),
(71,'Can delete log',18,'delete_log'),
(72,'Can view log',18,'view_log'),
(73,'Can add votes',19,'add_votes'),
(74,'Can change votes',19,'change_votes'),
(75,'Can delete votes',19,'delete_votes'),
(76,'Can view votes',19,'view_votes');
/*!40000 ALTER TABLE `auth_permission` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_user`
--

DROP TABLE IF EXISTS `auth_user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `password` varchar(128) NOT NULL,
  `last_login` datetime(6) DEFAULT NULL,
  `is_superuser` tinyint(1) NOT NULL,
  `username` varchar(150) NOT NULL,
  `first_name` varchar(150) NOT NULL,
  `last_name` varchar(150) NOT NULL,
  `email` varchar(254) NOT NULL,
  `is_staff` tinyint(1) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `date_joined` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_user`
--

LOCK TABLES `auth_user` WRITE;
/*!40000 ALTER TABLE `auth_user` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_user` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_user_groups`
--

DROP TABLE IF EXISTS `auth_user_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_user_groups` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `group_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_user_groups_user_id_group_id_94350c0c_uniq` (`user_id`,`group_id`),
  KEY `auth_user_groups_group_id_97559544_fk_auth_group_id` (`group_id`),
  CONSTRAINT `auth_user_groups_group_id_97559544_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`),
  CONSTRAINT `auth_user_groups_user_id_6a12ed8b_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_user_groups`
--

LOCK TABLES `auth_user_groups` WRITE;
/*!40000 ALTER TABLE `auth_user_groups` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_user_groups` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_user_user_permissions`
--

DROP TABLE IF EXISTS `auth_user_user_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_user_user_permissions` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `permission_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_user_user_permissions_user_id_permission_id_14a6b632_uniq` (`user_id`,`permission_id`),
  KEY `auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm` (`permission_id`),
  CONSTRAINT `auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  CONSTRAINT `auth_user_user_permissions_user_id_a95ead1b_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_user_user_permissions`
--

LOCK TABLES `auth_user_user_permissions` WRITE;
/*!40000 ALTER TABLE `auth_user_user_permissions` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_user_user_permissions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `blockchain_data`
--

DROP TABLE IF EXISTS `blockchain_data`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `blockchain_data` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `index` int(11) NOT NULL,
  `timestamp` varchar(100) NOT NULL,
  `data` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`data`)),
  `previous_hash` varchar(255) NOT NULL,
  `hash` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `blockchain_data`
--

LOCK TABLES `blockchain_data` WRITE;
/*!40000 ALTER TABLE `blockchain_data` DISABLE KEYS */;
/*!40000 ALTER TABLE `blockchain_data` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `candidates`
--

DROP TABLE IF EXISTS `candidates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `candidates` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `image` varchar(255) DEFAULT NULL,
  `campaign_message` longtext DEFAULT NULL,
  `department` longtext DEFAULT NULL,
  `year_level` varchar(255) DEFAULT NULL,
  `course` varchar(255) DEFAULT NULL,
  `skills` longtext DEFAULT NULL,
  `platform` longtext DEFAULT NULL,
  `goals` longtext DEFAULT NULL,
  `sg_years` varchar(255) DEFAULT NULL,
  `previous_role` varchar(255) DEFAULT NULL,
  `experience` longtext DEFAULT NULL,
  `achievements` longtext DEFAULT NULL,
  `slogan` longtext DEFAULT NULL,
  `note` longtext DEFAULT NULL,
  `edit_locked` tinyint(1) DEFAULT NULL,
  `position_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `candidates_position_id_b99e8a5d_fk_positions_id` (`position_id`),
  CONSTRAINT `candidates_position_id_b99e8a5d_fk_positions_id` FOREIGN KEY (`position_id`) REFERENCES `positions` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `candidates`
--

LOCK TABLES `candidates` WRITE;
/*!40000 ALTER TABLE `candidates` DISABLE KEYS */;
/*!40000 ALTER TABLE `candidates` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `classroom_positions`
--

DROP TABLE IF EXISTS `classroom_positions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `classroom_positions` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `course` varchar(255) DEFAULT NULL,
  `year_level` varchar(255) DEFAULT NULL,
  `section` varchar(255) DEFAULT NULL,
  `track` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `classroom_positions`
--

LOCK TABLES `classroom_positions` WRITE;
/*!40000 ALTER TABLE `classroom_positions` DISABLE KEYS */;
/*!40000 ALTER TABLE `classroom_positions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `classroom_settings`
--

DROP TABLE IF EXISTS `classroom_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `classroom_settings` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `course` varchar(255) DEFAULT NULL,
  `year_level` varchar(255) DEFAULT NULL,
  `section` varchar(255) DEFAULT NULL,
  `track` varchar(255) DEFAULT NULL,
  `filing_start` datetime(6) DEFAULT NULL,
  `filing_end` datetime(6) DEFAULT NULL,
  `filing_enabled` tinyint(1) DEFAULT NULL,
  `start_time` datetime(6) DEFAULT NULL,
  `end_time` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `classroom_settings`
--

LOCK TABLES `classroom_settings` WRITE;
/*!40000 ALTER TABLE `classroom_settings` DISABLE KEYS */;
/*!40000 ALTER TABLE `classroom_settings` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `classroom_votes`
--

DROP TABLE IF EXISTS `classroom_votes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `classroom_votes` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `student_id` varchar(255) NOT NULL,
  `candidate_id` varchar(255) NOT NULL,
  `candidate_ref` int(11) DEFAULT NULL,
  `course` varchar(255) DEFAULT NULL,
  `year_level` varchar(255) DEFAULT NULL,
  `section` varchar(255) DEFAULT NULL,
  `track` varchar(255) DEFAULT NULL,
  `created_at` datetime(6) DEFAULT NULL,
  `position_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `classroom_votes_position_id_32dd2bb7_fk_classroom_positions_id` (`position_id`),
  CONSTRAINT `classroom_votes_position_id_32dd2bb7_fk_classroom_positions_id` FOREIGN KEY (`position_id`) REFERENCES `classroom_positions` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `classroom_votes`
--

LOCK TABLES `classroom_votes` WRITE;
/*!40000 ALTER TABLE `classroom_votes` DISABLE KEYS */;
/*!40000 ALTER TABLE `classroom_votes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `dashboard_status`
--

DROP TABLE IF EXISTS `dashboard_status`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `dashboard_status` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `dashboard_name` varchar(50) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `dashboard_name` (`dashboard_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `dashboard_status`
--

LOCK TABLES `dashboard_status` WRITE;
/*!40000 ALTER TABLE `dashboard_status` DISABLE KEYS */;
/*!40000 ALTER TABLE `dashboard_status` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_admin_log`
--

DROP TABLE IF EXISTS `django_admin_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_admin_log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `action_time` datetime(6) NOT NULL,
  `object_id` longtext DEFAULT NULL,
  `object_repr` varchar(200) NOT NULL,
  `action_flag` smallint(5) unsigned NOT NULL CHECK (`action_flag` >= 0),
  `change_message` longtext NOT NULL,
  `content_type_id` int(11) DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `django_admin_log_content_type_id_c4bce8eb_fk_django_co` (`content_type_id`),
  KEY `django_admin_log_user_id_c564eba6_fk_auth_user_id` (`user_id`),
  CONSTRAINT `django_admin_log_content_type_id_c4bce8eb_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`),
  CONSTRAINT `django_admin_log_user_id_c564eba6_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_admin_log`
--

LOCK TABLES `django_admin_log` WRITE;
/*!40000 ALTER TABLE `django_admin_log` DISABLE KEYS */;
/*!40000 ALTER TABLE `django_admin_log` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_content_type`
--

DROP TABLE IF EXISTS `django_content_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_content_type` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `app_label` varchar(100) NOT NULL,
  `model` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `django_content_type_app_label_model_76bd3d3b_uniq` (`app_label`,`model`)
) ENGINE=InnoDB AUTO_INCREMENT=20 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_content_type`
--

LOCK TABLES `django_content_type` WRITE;
/*!40000 ALTER TABLE `django_content_type` DISABLE KEYS */;
INSERT INTO `django_content_type` VALUES
(1,'admin','logentry'),
(3,'auth','group'),
(2,'auth','permission'),
(4,'auth','user'),
(5,'contenttypes','contenttype'),
(6,'sessions','session'),
(16,'voting_app','candidate'),
(7,'voting_app','classroomposition'),
(8,'voting_app','classroomsettings'),
(15,'voting_app','classroomvotes'),
(9,'voting_app','dashboardstatus'),
(10,'voting_app','globalsettings'),
(18,'voting_app','log'),
(11,'voting_app','pendinguser'),
(12,'voting_app','position'),
(17,'voting_app','receiptaccesslogs'),
(13,'voting_app','settings'),
(14,'voting_app','user'),
(19,'voting_app','votes');
/*!40000 ALTER TABLE `django_content_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_migrations`
--

DROP TABLE IF EXISTS `django_migrations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_migrations` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `app` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `applied` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=21 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_migrations`
--

LOCK TABLES `django_migrations` WRITE;
/*!40000 ALTER TABLE `django_migrations` DISABLE KEYS */;
INSERT INTO `django_migrations` VALUES
(1,'contenttypes','0001_initial','2025-09-28 04:53:29.797331'),
(2,'auth','0001_initial','2025-09-28 04:53:30.054277'),
(3,'admin','0001_initial','2025-09-28 04:53:30.092462'),
(4,'admin','0002_logentry_remove_auto_add','2025-09-28 04:53:30.100829'),
(5,'admin','0003_logentry_add_action_flag_choices','2025-09-28 04:53:30.106608'),
(6,'contenttypes','0002_remove_content_type_name','2025-09-28 04:53:30.141670'),
(7,'auth','0002_alter_permission_name_max_length','2025-09-28 04:53:30.162147'),
(8,'auth','0003_alter_user_email_max_length','2025-09-28 04:53:30.174030'),
(9,'auth','0004_alter_user_username_opts','2025-09-28 04:53:30.181663'),
(10,'auth','0005_alter_user_last_login_null','2025-09-28 04:53:30.199231'),
(11,'auth','0006_require_contenttypes_0002','2025-09-28 04:53:30.200682'),
(12,'auth','0007_alter_validators_add_error_messages','2025-09-28 04:53:30.207537'),
(13,'auth','0008_alter_user_username_max_length','2025-09-28 04:53:30.219715'),
(14,'auth','0009_alter_user_last_name_max_length','2025-09-28 04:53:30.232503'),
(15,'auth','0010_alter_group_name_max_length','2025-09-28 04:53:30.244234'),
(16,'auth','0011_update_proxy_permissions','2025-09-28 04:53:30.251119'),
(17,'auth','0012_alter_user_first_name_max_length','2025-09-28 04:53:30.263438'),
(18,'sessions','0001_initial','2025-09-28 04:53:30.278831'),
(20,'voting_app','0001_initial','2025-09-28 07:52:17.142702');
/*!40000 ALTER TABLE `django_migrations` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_session`
--

DROP TABLE IF EXISTS `django_session`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_session` (
  `session_key` varchar(40) NOT NULL,
  `session_data` longtext NOT NULL,
  `expire_date` datetime(6) NOT NULL,
  PRIMARY KEY (`session_key`),
  KEY `django_session_expire_date_a5c62663` (`expire_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_session`
--

LOCK TABLES `django_session` WRITE;
/*!40000 ALTER TABLE `django_session` DISABLE KEYS */;
INSERT INTO `django_session` VALUES
('5r2jmu7qtb296f7020s0j3asndg8c6cp','e30:1v3DpK:ustpxCA9VtmdUZPR-lBIGgJtVDdqS7D18mkHBuH7jXA','2025-10-13 13:22:02.952437'),
('qrgr6l10v1ctqrlkxd5nvcrorfvrk7by','.eJw9jMsKwjAQRX8lzrpIU22i3QluBB-L4sJViXWMhdSGZAKW0n83PujqwrmcM4Ay6Khq0XulEYoBqLdxwYe6jhASoIbMh-w7rfHGToEinAQ4e3SsvJSb7WF3TFPOHsqzK-KTmZ_QBWL_2j0Y08--zRgg1VoouMzXQop8KeeLVcYlFwngyzYOfaVo-mU2_eP4BukFOdU:1v5QFn:9YRnCZBggqxcYN-ZC2-TCBvNuTo3em5uq-rvfXxaLYU','2025-10-19 15:02:27.384172'),
('veh7wen97ppug44snurw3qyrdda8c88b','eyJzY2hvb2xfaWQiOiJBRE1JTjAwMSIsInJvbGUiOiJhZG1pbiIsInVzZXJfaWQiOjJ9:1v53lK:UsmPfMZkZJX3C7HF0XyxxbtoR_xVLpTnBsouPtc8gyU','2025-10-18 15:01:30.281737'),
('wevrpyq39wyhc0pldqrap06u9110ov67','.eJw9jssOgkAMRX9l7JqYARWVnYkbEx8L4sIVGaHCJAND5pFICP9uRWHRNL3tPb09CIXGZTVaK0qEpAfXtdTB-jwnEQJw0qmvctZliQW7eUfibIC7RcPSR3o4Xk5XzkNWCcueiA1TP4P2jv1pL69UtxiZBHCibiEJt5t9TLUOl-TmO74KAN-tNGgz4aZ9HEbzfgjA5pXWKpMFBZgeE9boMakoatnQ6CnaeBMNH53CSLI:1v5Q68:ugDAqf9qCkrh9klFsgmuypV-iMmU1U2b_pFFhYgulLQ','2025-10-19 14:52:28.425948');
/*!40000 ALTER TABLE `django_session` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `global_settings`
--

DROP TABLE IF EXISTS `global_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `global_settings` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `voting_start` datetime(6) DEFAULT NULL,
  `voting_end` datetime(6) DEFAULT NULL,
  `filing_start` datetime(6) DEFAULT NULL,
  `filing_end` datetime(6) DEFAULT NULL,
  `voting_enabled` tinyint(1) DEFAULT NULL,
  `filing_enabled` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `global_settings`
--

LOCK TABLES `global_settings` WRITE;
/*!40000 ALTER TABLE `global_settings` DISABLE KEYS */;
INSERT INTO `global_settings` VALUES
(1,NULL,NULL,'2025-10-05 05:00:00.000000','2025-10-31 17:00:00.000000',1,1);
/*!40000 ALTER TABLE `global_settings` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `logs`
--

DROP TABLE IF EXISTS `logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `logs` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `action` varchar(100) NOT NULL,
  `target` longtext DEFAULT NULL,
  `table_name` varchar(50) DEFAULT NULL,
  `query_type` varchar(10) DEFAULT NULL,
  `new_data` longtext DEFAULT NULL,
  `old_data` longtext DEFAULT NULL,
  `timestamp` datetime(6) DEFAULT NULL,
  `user_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `logs_user_id_237f5f83_fk_user_id` (`user_id`),
  CONSTRAINT `logs_user_id_237f5f83_fk_user_id` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=482 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `logs`
--

LOCK TABLES `logs` WRITE;
/*!40000 ALTER TABLE `logs` DISABLE KEYS */;
INSERT INTO `logs` VALUES
(1,'LOGIN_SUCCESS','Login from IP 127.0.0.1 with role SysAdmin','user','SYSTEM','active=ACTIVE',NULL,'2025-10-04 14:29:19.634013',1),
(2,'ADMIN_REGISTRATION','Admin School ID: ADMIN001','user','INSERT','Email: ADMIN001@admin.local, Role: admin',NULL,'2025-10-04 14:29:58.545561',NULL),
(3,'LOGOUT','Logout from IP 127.0.0.1','user','UPDATE','active=OFFLINE',NULL,'2025-10-04 14:30:03.281872',1),
(4,'LOGIN_SUCCESS','Login from IP 127.0.0.1 with role admin','user','SYSTEM','active=ACTIVE',NULL,'2025-10-04 14:30:11.757709',2),
(5,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 14:30:13.656892',2),
(6,'APPROVE_USER','Pending User ID: 1','user','INSERT','School ID: asd, Email: yegan.kiru@gmail.com',NULL,'2025-10-04 14:41:52.459116',2),
(7,'DELETE_PENDING_USER','Pending User ID: 1','pending_users','DELETE','Reason: approved',NULL,'2025-10-04 14:41:57.179031',2),
(8,'LOGIN_SUCCESS','Login from IP 10.199.144.62 with role SysAdmin','user','SYSTEM','active=ACTIVE',NULL,'2025-10-04 15:00:57.034667',1),
(9,'LOGOUT','Logout from IP 10.199.144.62','user','UPDATE','active=OFFLINE',NULL,'2025-10-04 15:01:13.849648',1),
(10,'LOGIN_SUCCESS','Login from IP 10.199.144.62 with role admin','user','SYSTEM','active=ACTIVE',NULL,'2025-10-04 15:01:30.278715',2),
(11,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:01:32.235075',2),
(12,'LOGOUT','Logout from IP 127.0.0.1','user','UPDATE','active=OFFLINE',NULL,'2025-10-04 15:01:42.932947',2),
(13,'REGISTRATION_REQUEST','School ID: 23-13439, Email: ugheua@gmail.com','pending_users','INSERT','Registration submitted for approval',NULL,'2025-10-04 15:03:20.794229',NULL),
(14,'APPROVE_USER','Pending User ID: 2','user','INSERT','School ID: 23-13439, Email: ugheua@gmail.com',NULL,'2025-10-04 15:03:29.653688',2),
(15,'DELETE_PENDING_USER','Pending User ID: 2','pending_users','DELETE','Reason: approved',NULL,'2025-10-04 15:03:36.916271',2),
(16,'VIEW_ELECTION_RESULTS','Department: CCSICT','votes','READ','Viewed results for 0 positions with 0 total candidates',NULL,'2025-10-04 15:09:36.741009',2),
(17,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:09:39.640392',2),
(18,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:09:42.794947',2),
(19,'LOGIN_SUCCESS','Login from IP 127.0.0.1 with role admin','user','SYSTEM','active=ACTIVE',NULL,'2025-10-04 15:10:10.224485',2),
(20,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:10:12.112306',2),
(21,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:10:44.436917',2),
(22,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:12:44.764508',2),
(23,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:12:52.525837',2),
(24,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:13:05.209452',2),
(25,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:13:17.738683',2),
(26,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:13:30.292690',2),
(27,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:13:48.439708',2),
(28,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:13:50.219269',2),
(29,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:14:03.292371',2),
(30,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:14:03.470060',2),
(31,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:14:03.644111',2),
(32,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:14:03.966488',2),
(33,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:14:09.826137',2),
(34,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:14:10.229797',2),
(35,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:14:10.374498',2),
(36,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:14:10.519195',2),
(37,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:14:10.678763',2),
(38,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:14:12.991477',2),
(39,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:14:13.982803',2),
(40,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:14:14.805713',2),
(41,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:14:15.473760',2),
(42,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:16:48.006983',2),
(43,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:17:09.834337',2),
(44,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:17:33.889741',2),
(45,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:17:52.085656',2),
(46,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:18:05.706325',2),
(47,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:18:39.740566',2),
(48,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:18:59.377902',2),
(49,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:19:15.264456',2),
(50,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:19:29.056858',2),
(51,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:20:09.664393',2),
(52,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:21:24.409560',2),
(53,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:21:25.763030',2),
(54,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:29:15.392171',2),
(55,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:29:50.483430',2),
(56,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:32:11.268880',2),
(57,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:33:17.681806',2),
(58,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:33:24.211415',2),
(59,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:33:39.008537',2),
(60,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:33:42.542640',2),
(61,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:35:33.377167',2),
(62,'LOGIN_SUCCESS','Login from IP 127.0.0.1 with role admin','user','SYSTEM','active=ACTIVE',NULL,'2025-10-04 15:37:47.995921',2),
(63,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:37:49.894863',2),
(64,'LOGIN_SUCCESS','Login from IP 127.0.0.1 with role admin','user','SYSTEM','active=ACTIVE',NULL,'2025-10-04 15:40:29.724914',2),
(65,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:40:31.606203',2),
(66,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:40:36.952221',2),
(67,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:44:26.352524',2),
(68,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:46:03.156584',2),
(69,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:46:05.069251',2),
(70,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:46:07.094028',2),
(71,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:46:07.274905',2),
(72,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:47:11.002644',2),
(73,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:47:32.096264',2),
(74,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:47:34.345986',2),
(75,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:47:35.465335',2),
(76,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:47:42.675986',2),
(77,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:48:02.729623',2),
(78,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:48:44.107848',2),
(79,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:48:56.958150',2),
(80,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:49:09.110757',2),
(81,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:49:09.865222',2),
(82,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:49:10.213253',2),
(83,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:49:13.653019',2),
(84,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:49:26.879752',2),
(85,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:49:50.547200',2),
(86,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:49:51.763829',2),
(87,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-04 15:49:52.728877',2),
(88,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 05:56:02.049429',2),
(89,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 05:56:04.185015',2),
(90,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 05:56:05.751855',2),
(91,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 05:56:05.917244',2),
(92,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 05:56:36.225844',2),
(93,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 05:56:40.111448',2),
(94,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 05:56:42.269452',2),
(95,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 05:56:55.263772',2),
(96,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 05:56:56.769097',2),
(97,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 05:56:56.948596',2),
(98,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 05:56:57.120704',2),
(99,'LOGOUT','Logout from IP 127.0.0.1','user','UPDATE','active=OFFLINE',NULL,'2025-10-05 05:57:02.886368',2),
(100,'LOGIN_SUCCESS','Login from IP 127.0.0.1 with role admin','user','SYSTEM','active=ACTIVE',NULL,'2025-10-05 06:05:45.170404',2),
(101,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:05:47.056577',2),
(102,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:05:51.562236',2),
(103,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:05:51.745434',2),
(104,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:06:39.919062',2),
(105,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:06:56.193848',2),
(106,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:07:10.144966',2),
(107,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:07:29.082549',2),
(108,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:07:30.237405',2),
(109,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:08:19.860274',2),
(110,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:08:21.017157',2),
(111,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:08:45.792207',2),
(112,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:09:57.765722',2),
(113,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:10:09.525940',2),
(114,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:10:25.933267',2),
(115,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:10:43.984265',2),
(116,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:10:44.160045',2),
(117,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:10:48.138915',2),
(118,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:10:48.322415',2),
(119,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:10:48.479394',2),
(120,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:10:48.641112',2),
(121,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:12:08.349246',2),
(122,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:12:32.174115',2),
(123,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:12:33.343997',2),
(124,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:12:34.196249',2),
(125,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:12:53.387010',2),
(126,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:12:58.163277',2),
(127,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:14:16.966079',2),
(128,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:20:47.484772',2),
(129,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:20:47.553850',2),
(130,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:20:47.576346',2),
(131,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:20:48.981243',2),
(132,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:20:52.732779',2),
(133,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:20:52.938163',2),
(134,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:24:53.467478',2),
(135,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:24:54.099721',2),
(136,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:24:54.253341',2),
(137,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:33:30.309528',2),
(138,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:33:32.565430',2),
(139,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:33:35.969914',2),
(140,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:35:16.562650',2),
(141,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:36:00.973974',2),
(142,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:36:05.619833',2),
(143,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:36:07.287785',2),
(144,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:36:27.665090',2),
(145,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:36:39.322963',2),
(146,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:36:40.289451',2),
(147,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:36:58.043209',2),
(148,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:36:59.217178',2),
(149,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:37:11.642653',2),
(150,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:37:24.545724',2),
(151,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:37:28.065589',2),
(152,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:37:28.828943',2),
(153,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:37:43.247029',2),
(154,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:38:02.906819',2),
(155,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:38:30.887546',2),
(156,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:38:51.650277',2),
(157,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:39:52.912410',2),
(158,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:39:53.097688',2),
(159,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:39:55.359630',2),
(160,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:39:55.551493',2),
(161,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:40:35.357919',2),
(162,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:41:11.733294',2),
(163,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:41:58.710157',2),
(164,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:42:35.517997',2),
(165,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:42:41.867994',2),
(166,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:42:43.023002',2),
(167,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:43:44.491377',2),
(168,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:43:45.440574',2),
(169,'VIEW_ELECTION_RESULTS','Department: CCSICT','votes','READ','Viewed results for 0 positions with 0 total candidates',NULL,'2025-10-05 06:44:05.464869',2),
(170,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:44:08.633236',2),
(171,'VIEW_ELECTION_RESULTS','Department: CCSICT','votes','READ','Viewed results for 0 positions with 0 total candidates',NULL,'2025-10-05 06:44:17.985936',2),
(172,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:44:19.578735',2),
(173,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:44:24.782291',2),
(174,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:44:29.047898',2),
(175,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:44:37.649018',2),
(176,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:44:39.949052',2),
(177,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:44:40.911000',2),
(178,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:44:48.130735',2),
(179,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:44:57.468393',2),
(180,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:45:02.120341',2),
(181,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:45:07.835304',2),
(182,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:45:09.006311',2),
(183,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:45:15.102615',2),
(184,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:45:16.250123',2),
(185,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:45:17.435604',2),
(186,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:45:24.421828',2),
(187,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:45:51.256677',2),
(188,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:45:52.121658',2),
(189,'VIEW_ACTIVITY_LOGS','Role: admin, Department: CCSICT','logs','READ','Viewed 0 activity logs',NULL,'2025-10-05 06:45:54.991479',2),
(190,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:45:56.472823',2),
(191,'VIEW_ACTIVITY_LOGS','Role: admin, Department: CCSICT','logs','READ','Viewed 0 activity logs',NULL,'2025-10-05 06:45:58.494739',2),
(192,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:46:02.844952',2),
(193,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:46:07.956701',2),
(194,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:46:09.165781',2),
(195,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:46:11.644126',2),
(196,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:46:23.497447',2),
(197,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:46:37.310821',2),
(198,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:46:42.001117',2),
(199,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:46:43.265136',2),
(200,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:46:43.435087',2),
(201,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:47:48.460718',2),
(202,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:47:49.634093',2),
(203,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:47:50.833326',2),
(204,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:47:52.003393',2),
(205,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:48:06.104734',2),
(206,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:48:16.709317',2),
(207,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:48:17.798579',2),
(208,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:50:37.502148',2),
(209,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:50:45.667439',2),
(210,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:50:50.143324',2),
(211,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:50:50.309795',2),
(212,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:50:53.929711',2),
(213,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:51:02.261060',2),
(214,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:51:02.398558',2),
(215,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:51:02.546848',2),
(216,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:51:08.076234',2),
(217,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:51:15.773296',2),
(218,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:51:26.797511',2),
(219,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:51:27.980912',2),
(220,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:51:37.373837',2),
(221,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:51:42.067349',2),
(222,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:51:43.241125',2),
(223,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:51:54.613264',2),
(224,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:51:54.776963',2),
(225,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:51:54.959517',2),
(226,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:51:59.702137',2),
(227,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:52:07.068510',2),
(228,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:52:09.390747',2),
(229,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:52:25.888772',2),
(230,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:52:27.025065',2),
(231,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:52:28.238366',2),
(232,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:52:34.148700',2),
(233,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:52:42.445505',2),
(234,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:52:43.601856',2),
(235,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:52:46.968023',2),
(236,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:52:47.217077',2),
(237,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:52:47.380563',2),
(238,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:52:57.949093',2),
(239,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:53:01.068122',2),
(240,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:54:46.083056',2),
(241,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:54:58.948091',2),
(242,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:55:00.065087',2),
(243,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:55:01.077108',2),
(244,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:55:05.971457',2),
(245,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:55:10.421034',2),
(246,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:55:14.083875',2),
(247,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:55:15.380649',2),
(248,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:55:25.915888',2),
(249,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:55:30.542296',2),
(250,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:55:32.553727',2),
(251,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:55:39.962475',2),
(252,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:55:53.975785',2),
(253,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:55:56.284824',2),
(254,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:56:06.943893',2),
(255,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:56:08.067765',2),
(256,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:56:08.556766',2),
(257,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:56:24.376343',2),
(258,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:56:26.764938',2),
(259,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:56:27.658704',2),
(260,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:56:38.506914',2),
(261,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:56:40.163798',2),
(262,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:56:40.333252',2),
(263,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:56:53.734804',2),
(264,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:56:59.652964',2),
(265,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:57:00.725835',2),
(266,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:57:00.882123',2),
(267,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:57:48.894974',2),
(268,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:58:01.970501',2),
(269,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:58:03.458829',2),
(270,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:58:24.331452',2),
(271,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:58:25.007033',2),
(272,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:58:29.743948',2),
(273,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:59:38.392016',2),
(274,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:59:39.536698',2),
(275,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:59:48.809882',2),
(276,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:59:49.989341',2),
(277,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:59:50.940126',2),
(278,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:59:56.963883',2),
(279,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:59:58.104567',2),
(280,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 06:59:59.907188',2),
(281,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:00:00.074618',2),
(282,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:00:18.291435',2),
(283,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:00:19.071185',2),
(284,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:00:26.660516',2),
(285,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:00:27.838751',2),
(286,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:00:28.920458',2),
(287,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:00:29.064410',2),
(288,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:00:37.247789',2),
(289,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:00:53.600493',2),
(290,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:00:55.360946',2),
(291,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:00:55.544342',2),
(292,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:01:31.543106',2),
(293,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:01:33.474926',2),
(294,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:01:39.760045',2),
(295,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:01:41.110763',2),
(296,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:01:57.414293',2),
(297,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:02:16.230565',2),
(298,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:02:35.065581',2),
(299,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:02:54.218671',2),
(300,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:03:13.948741',2),
(301,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:03:16.109330',2),
(302,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:04:01.226584',2),
(303,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:04:13.569882',2),
(304,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:04:13.725478',2),
(305,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:04:21.227115',2),
(306,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:04:39.837335',2),
(307,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:04:55.063935',2),
(308,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:04:56.254455',2),
(309,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:04:57.514029',2),
(310,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:04:57.722839',2),
(311,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:04:57.811697',2),
(312,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:05:02.099184',2),
(313,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:05:35.878753',2),
(314,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:05:38.158503',2),
(315,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:05:39.040529',2),
(316,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:05:48.573867',2),
(317,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:06:01.476420',2),
(318,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:06:20.209757',2),
(319,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:06:34.324604',2),
(320,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:06:47.208001',2),
(321,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:06:50.066609',2),
(322,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:06:50.252233',2),
(323,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:06:50.442008',2),
(324,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:07:22.461161',2),
(325,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:07:34.208164',2),
(326,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:07:38.808545',2),
(327,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:07:39.940367',2),
(328,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:07:55.025045',2),
(329,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:07:56.205570',2),
(330,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:10:10.419054',2),
(331,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:10:20.993994',2),
(332,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:10:24.506178',2),
(333,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:10:38.504816',2),
(334,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:11:01.950489',2),
(335,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:11:05.258004',2),
(336,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:11:08.987120',2),
(337,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:11:20.640023',2),
(338,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:11:21.815064',2),
(339,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:11:24.159563',2),
(340,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:11:27.694697',2),
(341,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:11:32.331588',2),
(342,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:11:35.823138',2),
(343,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:12:08.646795',2),
(344,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:12:12.173844',2),
(345,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:12:13.862570',2),
(346,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:12:52.823895',2),
(347,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:13:23.163828',2),
(348,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:13:58.248812',2),
(349,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:14:13.993173',2),
(350,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:14:22.159865',2),
(351,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:14:22.321153',2),
(352,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:14:28.026899',2),
(353,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:14:44.180481',2),
(354,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:15:18.157653',2),
(355,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:16:09.391969',2),
(356,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:16:43.595222',2),
(357,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:17:01.125407',2),
(358,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:17:16.484540',2),
(359,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:17:40.948176',2),
(360,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:17:54.871847',2),
(361,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:18:15.972782',2),
(362,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:18:19.478384',2),
(363,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:18:22.982989',2),
(364,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:18:28.769381',2),
(365,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:18:29.942247',2),
(366,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:18:31.116172',2),
(367,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:18:36.769935',2),
(368,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:18:36.948014',2),
(369,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:18:37.071841',2),
(370,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:18:53.377159',2),
(371,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:19:26.004348',2),
(372,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:19:43.254342',2),
(373,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:20:13.832689',2),
(374,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:20:15.069730',2),
(375,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:20:15.243173',2),
(376,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:20:17.353476',2),
(377,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:20:38.337487',2),
(378,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:21:02.970296',2),
(379,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:21:13.448124',2),
(380,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:21:33.438542',2),
(381,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:21:54.556051',2),
(382,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:21:59.155450',2),
(383,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:22:00.229978',2),
(384,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:22:00.399254',2),
(385,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:22:21.363969',2),
(386,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:22:40.096935',2),
(387,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:22:58.738179',2),
(388,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:23:21.088180',2),
(389,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:24:22.285048',2),
(390,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:24:46.968496',2),
(391,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:25:03.491133',2),
(392,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:25:04.619550',2),
(393,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:25:04.948361',2),
(394,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:34:21.693956',2),
(395,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:34:21.695971',2),
(396,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:34:21.696971',2),
(397,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:34:21.699968',2),
(398,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:34:21.700974',2),
(399,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:35:10.190443',2),
(400,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:35:19.593297',2),
(401,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:41:37.062374',2),
(402,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:41:37.363980',2),
(403,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:51:08.296322',2),
(404,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:51:22.738728',2),
(405,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:51:52.482925',2),
(406,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:51:59.724834',2),
(407,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 07:51:59.831338',2),
(408,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 08:06:32.407260',2),
(409,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 08:06:36.328827',2),
(410,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 08:38:31.979084',2),
(411,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 08:39:37.726973',2),
(412,'FETCH_CANDIDATES','Role: admin','candidates','READ','0 positions fetched',NULL,'2025-10-05 08:39:39.842095',2),
(413,'FETCH_CANDIDATES','Role: admin','candidates','READ','0 positions fetched',NULL,'2025-10-05 08:39:42.482877',2),
(414,'FETCH_CANDIDATES','Role: admin','candidates','READ','0 positions fetched',NULL,'2025-10-05 08:39:43.159972',2),
(415,'FETCH_CANDIDATES','Role: admin','candidates','READ','0 positions fetched',NULL,'2025-10-05 08:39:43.651710',2),
(416,'FETCH_CANDIDATES','Role: admin','candidates','READ','0 positions fetched',NULL,'2025-10-05 08:39:43.871506',2),
(417,'FETCH_CANDIDATES','Role: admin','candidates','READ','0 positions fetched',NULL,'2025-10-05 08:39:44.469518',2),
(418,'FETCH_CANDIDATES','Role: admin','candidates','READ','0 positions fetched',NULL,'2025-10-05 08:39:44.691508',2),
(419,'FETCH_CANDIDATES','Role: admin','candidates','READ','0 positions fetched',NULL,'2025-10-05 08:39:45.105922',2),
(420,'FETCH_CANDIDATES','Role: admin','candidates','READ','0 positions fetched',NULL,'2025-10-05 08:39:45.614891',2),
(421,'FETCH_CANDIDATES','Role: admin','candidates','READ','0 positions fetched',NULL,'2025-10-05 08:39:46.078893',2),
(422,'FETCH_CANDIDATES','Role: admin','candidates','READ','0 positions fetched',NULL,'2025-10-05 08:39:46.626309',2),
(423,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 08:41:31.104246',2),
(424,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 08:41:47.386904',2),
(425,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 08:41:58.018221',2),
(426,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 08:42:20.370385',2),
(427,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 08:42:39.027181',2),
(428,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 08:42:40.239202',2),
(429,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 08:42:41.717816',2),
(430,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 08:42:41.920659',2),
(431,'FETCH_CANDIDATES','Role: admin','candidates','READ','0 positions fetched',NULL,'2025-10-05 08:42:43.607184',2),
(432,'FETCH_CANDIDATES','Role: admin','candidates','READ','0 positions fetched',NULL,'2025-10-05 08:42:45.598740',2),
(433,'FETCH_CANDIDATES','Role: admin','candidates','READ','0 positions fetched',NULL,'2025-10-05 08:42:48.963271',2),
(434,'FETCH_CANDIDATES','Role: admin','candidates','READ','0 positions fetched',NULL,'2025-10-05 08:42:51.250452',2),
(435,'FETCH_CANDIDATES','Role: admin','candidates','READ','0 positions fetched',NULL,'2025-10-05 08:42:52.342709',2),
(436,'FETCH_CANDIDATES','Role: admin','candidates','READ','0 positions fetched',NULL,'2025-10-05 08:42:53.560874',2),
(437,'FETCH_CANDIDATES','Role: admin','candidates','READ','0 positions fetched',NULL,'2025-10-05 08:42:54.746889',2),
(438,'FETCH_CANDIDATES','Role: admin','candidates','READ','0 positions fetched',NULL,'2025-10-05 08:42:56.144131',2),
(439,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 08:50:20.998797',2),
(440,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 08:50:34.067772',2),
(441,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 08:50:53.899561',2),
(442,'LOGOUT','Logout from IP 127.0.0.1','user','UPDATE','active=OFFLINE',NULL,'2025-10-05 09:05:41.105021',2),
(443,'LOGIN_SUCCESS','Login from IP 127.0.0.1 with role SysAdmin','user','SYSTEM','active=ACTIVE',NULL,'2025-10-05 09:05:45.976035',1),
(444,'FILING_PERIOD_SET','Global filing period','global_settings','INSERT','Start: 2025-11-01 12:59:00, End: 2026-12-25 10:58:00',NULL,'2025-10-05 09:06:35.618180',NULL),
(445,'LOGOUT','Logout from IP 127.0.0.1','user','UPDATE','active=OFFLINE',NULL,'2025-10-05 09:06:43.280920',1),
(446,'LOGIN_SUCCESS','Login from IP 127.0.0.1 with role admin','user','SYSTEM','active=ACTIVE',NULL,'2025-10-05 09:06:49.268307',2),
(447,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 09:06:51.197595',2),
(448,'LOGOUT','Logout from IP 127.0.0.1','user','UPDATE','active=OFFLINE',NULL,'2025-10-05 09:15:03.987920',2),
(449,'LOGIN_SUCCESS','Login from IP 127.0.0.1 with role SysAdmin','user','SYSTEM','active=ACTIVE',NULL,'2025-10-05 09:15:08.602470',1),
(450,'LOGOUT','Logout from IP 127.0.0.1','user','UPDATE','active=OFFLINE',NULL,'2025-10-05 09:16:11.381732',1),
(451,'LOGIN_SUCCESS','Login from IP 127.0.0.1 with role admin','user','SYSTEM','active=ACTIVE',NULL,'2025-10-05 09:16:17.715965',2),
(452,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 09:16:19.664191',2),
(453,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 09:39:27.721189',2),
(454,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 09:39:30.548446',2),
(455,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 09:39:30.741859',2),
(456,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 09:39:37.057043',2),
(457,'LOGOUT','Logout from IP 127.0.0.1','user','UPDATE','active=OFFLINE',NULL,'2025-10-05 09:40:35.013922',2),
(458,'LOGIN_SUCCESS','Login from IP 127.0.0.1 with role SysAdmin','user','SYSTEM','active=ACTIVE',NULL,'2025-10-05 09:40:42.769139',1),
(459,'FILING_PERIOD_UNEXPECTED_ERROR','Unexpected error during filing period setup','settings, global_settings','ERROR','Error: can\'t compare offset-naive and offset-aware datetimes',NULL,'2025-10-05 09:41:54.218875',NULL),
(460,'FILING_PERIOD_UNEXPECTED_ERROR','Unexpected error during filing period setup','settings, global_settings','ERROR','Error: can\'t compare offset-naive and offset-aware datetimes',NULL,'2025-10-05 09:42:49.930841',NULL),
(461,'FILING_PERIOD_UNEXPECTED_ERROR','Unexpected error during filing period setup','settings, global_settings','ERROR','Error: can\'t compare offset-naive and offset-aware datetimes',NULL,'2025-10-05 09:49:32.792730',NULL),
(462,'FILING_PERIOD_SET','Global filing period','global_settings','INSERT','Start: 2025-10-05 13:00:00, End: 2025-11-01 01:00:00',NULL,'2025-10-05 14:45:43.939684',NULL),
(463,'LOGOUT','Logout from IP 127.0.0.1','user','UPDATE','active=OFFLINE',NULL,'2025-10-05 14:52:20.998079',1),
(464,'LOGIN_SUCCESS','Login from IP 127.0.0.1 with role admin','user','SYSTEM','active=ACTIVE',NULL,'2025-10-05 14:52:28.417785',2),
(465,'VIEW_ADMIN_DASHBOARD','Department: CCSICT','user','READ','Fetched 0 active users',NULL,'2025-10-05 14:52:30.359710',2),
(466,'LOGIN_SUCCESS','Login from IP 127.0.0.1 with role SysAdmin','user','SYSTEM','active=ACTIVE',NULL,'2025-10-05 15:02:12.971327',1),
(467,'LOGOUT','Logout from IP 127.0.0.1','user','UPDATE','active=OFFLINE',NULL,'2025-10-05 15:02:27.379174',1),
(468,'VIEW_ELECTION_RESULTS','Department: CCSICT','votes','READ','Viewed results for 0 positions with 0 total candidates',NULL,'2025-10-05 15:21:33.951754',2),
(469,'VIEW_ELECTION_RESULTS','Department: CCSICT','votes','READ','Viewed results for 0 positions with 0 total candidates',NULL,'2025-10-05 15:23:09.729699',2),
(470,'VIEW_ELECTION_RESULTS','Department: CCSICT','votes','READ','Viewed results for 0 positions with 0 total candidates',NULL,'2025-10-05 15:23:57.801831',2),
(471,'VIEW_ELECTION_RESULTS','Department: CCSICT','votes','READ','Viewed results for 0 positions with 0 total candidates',NULL,'2025-10-05 15:24:11.021321',2),
(472,'VIEW_ELECTION_RESULTS','Department: CCSICT','votes','READ','Viewed results for 0 positions with 0 total candidates',NULL,'2025-10-05 15:24:31.246383',2),
(473,'VIEW_ELECTION_RESULTS','Department: CCSICT','votes','READ','Viewed results for 0 positions with 0 total candidates',NULL,'2025-10-05 15:24:32.150072',2),
(474,'VIEW_ELECTION_RESULTS','Department: CCSICT','votes','READ','Viewed results for 0 positions with 0 total candidates',NULL,'2025-10-05 15:24:32.300042',2),
(475,'VIEW_ELECTION_RESULTS','Department: CCSICT','votes','READ','Viewed results for 0 positions with 0 total candidates',NULL,'2025-10-05 15:24:32.519024',2),
(476,'VIEW_ELECTION_RESULTS','Department: CCSICT','votes','READ','Viewed results for 0 positions with 0 total candidates',NULL,'2025-10-05 15:24:50.741808',2),
(477,'VIEW_ELECTION_RESULTS','Department: CCSICT','votes','READ','Viewed results for 0 positions with 0 total candidates',NULL,'2025-10-05 15:24:50.959960',2),
(478,'VIEW_ELECTION_RESULTS','Department: CCSICT','votes','READ','Viewed results for 0 positions with 0 total candidates',NULL,'2025-10-05 15:24:55.020057',2),
(479,'VIEW_ELECTION_RESULTS','Department: CCSICT','votes','READ','Viewed results for 0 positions with 0 total candidates',NULL,'2025-10-05 15:26:11.932218',2),
(480,'VIEW_ELECTION_RESULTS','Department: CCSICT','votes','READ','Viewed results for 0 positions with 0 total candidates',NULL,'2025-10-05 15:26:12.845703',2),
(481,'VIEW_ELECTION_RESULTS','Department: CCSICT','votes','READ','Viewed results for 0 positions with 0 total candidates',NULL,'2025-10-05 15:26:14.788335',2);
/*!40000 ALTER TABLE `logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `pending_users`
--

DROP TABLE IF EXISTS `pending_users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `pending_users` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `school_id` varchar(50) NOT NULL,
  `course` varchar(100) DEFAULT NULL,
  `email` varchar(255) NOT NULL,
  `password_plain` longtext NOT NULL,
  `first_name` varchar(100) DEFAULT NULL,
  `last_name` varchar(100) DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `id_photo_front` longtext DEFAULT NULL,
  `id_photo_back` longtext DEFAULT NULL,
  `submitted_at` datetime(6) DEFAULT NULL,
  `course_code` varchar(255) DEFAULT NULL,
  `track` varchar(255) DEFAULT NULL,
  `department` varchar(255) DEFAULT NULL,
  `year_level` varchar(255) DEFAULT NULL,
  `section` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `pending_users`
--

LOCK TABLES `pending_users` WRITE;
/*!40000 ALTER TABLE `pending_users` DISABLE KEYS */;
/*!40000 ALTER TABLE `pending_users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `positions`
--

DROP TABLE IF EXISTS `positions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `positions` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `department` varchar(100) NOT NULL,
  `course` varchar(255) DEFAULT NULL,
  `year_level` varchar(255) DEFAULT NULL,
  `section` varchar(255) DEFAULT NULL,
  `track` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `positions`
--

LOCK TABLES `positions` WRITE;
/*!40000 ALTER TABLE `positions` DISABLE KEYS */;
INSERT INTO `positions` VALUES
(1,'Test Position','TEST_DEPT','Test Course',NULL,NULL,NULL);
/*!40000 ALTER TABLE `positions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `receipt_access_logs`
--

DROP TABLE IF EXISTS `receipt_access_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `receipt_access_logs` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `school_id` varchar(50) NOT NULL,
  `viewed_at` datetime(6) NOT NULL,
  `expired_at` datetime(6) NOT NULL,
  `status` varchar(50) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `receipt_access_logs_status_check` CHECK (`status` in ('active','expired'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `receipt_access_logs`
--

LOCK TABLES `receipt_access_logs` WRITE;
/*!40000 ALTER TABLE `receipt_access_logs` DISABLE KEYS */;
/*!40000 ALTER TABLE `receipt_access_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `settings`
--

DROP TABLE IF EXISTS `settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `settings` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `department` varchar(50) NOT NULL,
  `voting_deadline` datetime(6) DEFAULT NULL,
  `start_time` datetime(6) DEFAULT NULL,
  `end_time` datetime(6) DEFAULT NULL,
  `filing_start` datetime(6) DEFAULT NULL,
  `filing_end` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `settings`
--

LOCK TABLES `settings` WRITE;
/*!40000 ALTER TABLE `settings` DISABLE KEYS */;
/*!40000 ALTER TABLE `settings` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user`
--

DROP TABLE IF EXISTS `user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `school_id` varchar(50) NOT NULL,
  `course` varchar(100) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password_hash` longtext NOT NULL,
  `first_name` varchar(100) NOT NULL,
  `last_name` varchar(100) NOT NULL,
  `phone` varchar(20) NOT NULL,
  `id_photo_front` longtext NOT NULL,
  `id_photo_back` longtext NOT NULL,
  `role` varchar(20) NOT NULL,
  `created_at` datetime(6) DEFAULT NULL,
  `course_code` varchar(255) DEFAULT NULL,
  `track` varchar(255) DEFAULT NULL,
  `year_level` varchar(255) DEFAULT NULL,
  `department` varchar(255) DEFAULT NULL,
  `active` varchar(50) DEFAULT NULL,
  `reset_token` longtext DEFAULT NULL,
  `reset_token_expiry` longtext DEFAULT NULL,
  `reset_otp` longtext DEFAULT NULL,
  `reset_otp_expiry` datetime(6) DEFAULT NULL,
  `section` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `school_id` (`school_id`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `phone` (`phone`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user`
--

LOCK TABLES `user` WRITE;
/*!40000 ALTER TABLE `user` DISABLE KEYS */;
INSERT INTO `user` VALUES
(1,'SYSADMIN001','Global Administration','sysadmin@global.local','scrypt:32768:8:1$ih8XrKyQWgPc2PaW$b4e105b08cd40c9fc76f84e8d8817a6add2e9476145eb3e9f5fb83f726bd2d2cb8a8fc4c8282663f7c2273758b17d0cd1f0fc91cdfe15b57b6a11727d9e78166','System','Administrator','0000000000','placeholder_front.jpg','placeholder_back.jpg','SysAdmin',NULL,NULL,NULL,NULL,NULL,'OFFLINE',NULL,NULL,NULL,NULL,NULL),
(2,'ADMIN001','CCSICT','ADMIN001@admin.local','scrypt:32768:8:1$RWzlZp5P3W1oNalr$840e57b77b7b55613bc96a29c862b2e9af4287492b7035ab4a313dcd42c3da00df8576482f7c8d8d7968f89ee415d04e71b5811dd44f4e5eac54518d24ffea98','Sam','Porter Bridges','adm-2ab325','N/A','N/A','admin','2025-10-04 14:29:58.542561',NULL,NULL,NULL,'CCSICT','ACTIVE',NULL,NULL,NULL,NULL,NULL),
(3,'asd','Bachelor of Science in Information Technology','yegan.kiru@gmail.com','scrypt:32768:8:1$AX4HNtB9u7TMwi0U$db89d0c5f639d8922bcbbdf2e7d62b3ace9f0a63466d7302768351081efb2f657573b08d3c30b949e085a84aad82de3cef612ef23be13c6a43f99b75d7542056','Hadush','Alfarashad','09911','C:\\Users\\maday\\PROJECTS\\UNI_Django\\static\\uploads\\school_ids\\asd_front_Screenshot_2025_0927_152320.png','C:\\Users\\maday\\PROJECTS\\UNI_Django\\static\\uploads\\school_ids\\asd_back_Screenshot_2025_0927_152320.png','user','2025-10-04 14:41:52.443039','BSIT','Networking and Security','3rd Year','CCSICT','OFFLINE',NULL,NULL,NULL,NULL,'3A'),
(4,'23-13439','Bachelor of Science in Information Technology','ugheua@gmail.com','scrypt:32768:8:1$KQ99FucxFlc3vO2K$3075dec31f8e972434e008b6913521fbb28f7b66e5d2287ef7a691e2b44f60b40d5fcc8e8983fbc723dcdce165ce7ec2f39f49988d2524b9989e6b0b16af213c','Ako Moscov','User','5465452465','C:\\Users\\maday\\PROJECTS\\UNI_Django\\static\\uploads\\school_ids\\23-13439_front_IMG_20251003_211737.jpg','C:\\Users\\maday\\PROJECTS\\UNI_Django\\static\\uploads\\school_ids\\23-13439_back_IMG_20251003_211737.jpg','user','2025-10-04 15:03:29.648384','BSIT','Networking and Security','3rd Year','CCSICT','OFFLINE',NULL,NULL,NULL,NULL,'3A');
/*!40000 ALTER TABLE `user` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `votes`
--

DROP TABLE IF EXISTS `votes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `votes` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `student_id` varchar(50) DEFAULT NULL,
  `candidate_id` longtext DEFAULT NULL,
  `department` varchar(100) DEFAULT NULL,
  `candidate_ref_id` bigint(20) DEFAULT NULL,
  `position_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `votes_candidate_ref_id_abebb0a9_fk_candidates_id` (`candidate_ref_id`),
  KEY `votes_position_id_0fafd315_fk_positions_id` (`position_id`),
  CONSTRAINT `votes_candidate_ref_id_abebb0a9_fk_candidates_id` FOREIGN KEY (`candidate_ref_id`) REFERENCES `candidates` (`id`),
  CONSTRAINT `votes_position_id_0fafd315_fk_positions_id` FOREIGN KEY (`position_id`) REFERENCES `positions` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `votes`
--

LOCK TABLES `votes` WRITE;
/*!40000 ALTER TABLE `votes` DISABLE KEYS */;
/*!40000 ALTER TABLE `votes` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*M!100616 SET NOTE_VERBOSITY=@OLD_NOTE_VERBOSITY */;

-- Dump completed on 2025-10-06 20:03:22
