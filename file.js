/*
CREATE TABLE
  `issue_master` (
    `issue_master_id` int NOT NULL AUTO_INCREMENT,
    `issue_master_key` varchar(30) DEFAULT NULL,
    `issue_title` varchar(300) NOT NULL,
    `description` text NOT NULL,
    `impact` text,
    `recommendation` text,
    `owasp_ref_no` text CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci,
    `cwe_cve_ref_no` varchar(255) DEFAULT NULL,
    `appl_type` int NOT NULL DEFAULT '-1',
    `audit_methodology_type` int NOT NULL DEFAULT '200',
    `created_by_id` int NOT NULL,
    `created_on` datetime NOT NULL,
    `updated_on` datetime DEFAULT NULL,
    `is_updated` enum('1', '0') DEFAULT '0',
    `updated_by_user` enum('yes', 'no') DEFAULT 'no',
    `deleted_on` datetime DEFAULT NULL,
    PRIMARY KEY (`issue_master_id`),
    KEY `issue_master_id` (`issue_master_id`)
  ) ENGINE = InnoDB AUTO_INCREMENT = 68 DEFAULT CHARSET = utf8mb3
*/
