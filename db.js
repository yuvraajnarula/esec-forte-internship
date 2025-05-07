require('dotenv').config();
const { Sequelize } = require('sequelize');
const { faker } = require('@faker-js/faker');
const path = require('path');
const fs = require('fs');
const csv = require('csv-parse/sync'); 
const sequelize = new Sequelize(
    process.env.DB_NAME,
    process.env.DB_USER,
    process.env.DB_PASSWORD,
    {
        host: process.env.DB_HOST,
        dialect: 'mysql',
        logging: false,
        pool: {
            max: 20,
            min: 0,
            acquire: 60000,
            idle: 10000
        }
    }
);

async function databaseExists(dbName) {
    const [results] = await sequelize.query(
        `SELECT SCHEMA_NAME
         FROM INFORMATION_SCHEMA.SCHEMATA
        WHERE SCHEMA_NAME = :dbName`,
        {
            replacements: { dbName },
            type: Sequelize.QueryTypes.SELECT,
        }
    );
    return results !== undefined;
}

function createDatabase(dbName) {
    sequelize.query(`CREATE DATABASE IF NOT EXISTS ${dbName}`)
        .then(() => {
            console.log(`Database ${dbName} created successfully.`);
        })
        .catch((error) => {
            console.error('Error creating database:', error);
        });
}

const rows = 100000;
const BATCH_SIZE = 1000;

async function dataInjection(dbName) {
    try {
        await sequelize.query(`USE ${dbName}`);
        console.log(`Database ${dbName} selected successfully.`);

        await sequelize.query(`
            CREATE TABLE IF NOT EXISTS issue_master (
                issue_master_id INT NOT NULL AUTO_INCREMENT,
                issue_master_key varchar(30) DEFAULT NULL,
                issue_title VARCHAR(255) NOT NULL,
                description text NOT NULL,
                impact TEXT,
                recommendation text,
                owasp_ref_no text CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci,
                cwe_cve_ref_no varchar(255) DEFAULT NULL,
                appl_type int NOT NULL DEFAULT '-1',
                audit_methodology_type int NOT NULL DEFAULT '200',
                created_by_id int NOT NULL,
                created_on datetime NOT NULL,
                updated_on datetime DEFAULT NULL,
                is_updated enum('1', '0') DEFAULT '0',
                updated_by_user enum('yes', 'no') DEFAULT 'no',
                deleted_on datetime DEFAULT NULL,
                PRIMARY KEY (issue_master_id),
                KEY issue_master_id (issue_master_id)
            ) ENGINE = InnoDB AUTO_INCREMENT = 68 DEFAULT CHARSET = utf8mb3
        `);
        console.log(`Table 'issue_master' created successfully.`);
        const [countResult] = await sequelize.query(
            `SELECT COUNT(*) as count FROM issue_master`,
            {
                type: Sequelize.QueryTypes.SELECT
            }
        );
        if (countResult.count > 0) {
            console.log('Table "issue_master" already contains data. Skipping data injection.');
            return;
        }
    } catch (error) {
        console.error('Error during data injection:', error);
    } 
}

module.exports = { sequelize, databaseExists, createDatabase, dataInjection };