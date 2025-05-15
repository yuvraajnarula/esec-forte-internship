require('dotenv').config();
const { Sequelize, DataTypes } = require('sequelize');
const winston = require('winston');

// Initialize logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} [${level.toUpperCase()}]: ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'database.log' }),
  ],
});

// Vulnerabilities list
const vulnerabilitiesList = [
    "SQL Injection (SQLi)",
    "Cross-Site Scripting (XSS)",
    "Cross-Site Request Forgery (CSRF)",
    "Broken Authentication and Session Management",
    "Insecure Direct Object References (IDOR)",
    "Security Misconfiguration",
    "Sensitive Data Exposure",
    "Using Components with Known Vulnerabilities",
    "Insecure Deserialization",
    "Insufficient Logging & Monitoring",
    "Server-Side Request Forgery (SSRF)",
    "XML External Entity (XXE) Injection",
    "Unvalidated Redirects & Forwards",
    "Privilege Escalation",
    "Business Logic Flaws",
    "API Vulnerabilities",
    "Inadequate Input Validation",
    "Weak Password Policies",
    "Unencrypted Sensitive Data at Rest",
    "Improper Error Handling",
    "Directory Traversal",
    "Clickjacking",
    "Memory Corruption (Buffer Overflows)",
    "Race Conditions",
    "Certificate & TLS Misconfigurations",
    "Open Redirects",
    "Hard-Coded Credentials",
    "Insufficient Session Expiration",
    "Client-Side Security Bypass",
    "Cloud Misconfigurations"
];

// Sequelize setup
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
      idle: 10000,
    },
  }
);

const IssueMaster = sequelize.define('issue_master', {
  issue_master_id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  issue_master_key: DataTypes.STRING,
  issue_title: { type: DataTypes.STRING, allowNull: false, unique: true },
  description: DataTypes.TEXT,
  impact: DataTypes.TEXT,
  recommendation: DataTypes.TEXT,
  owasp_ref_no: DataTypes.STRING,
  cwe_cve_ref_no: DataTypes.STRING,
  appl_type: { type: DataTypes.INTEGER, defaultValue: -1 },
  audit_methodology_type: { type: DataTypes.INTEGER, defaultValue: 200 },
  created_by_id: DataTypes.INTEGER,
  created_on: DataTypes.DATE,
  updated_on: DataTypes.DATE,
  is_updated: { type: DataTypes.ENUM('1', '0'), defaultValue: '0' },
  updated_by_user: { type: DataTypes.ENUM('yes', 'no'), defaultValue: 'no' },
  deleted_on: DataTypes.DATE,
}, {
  tableName: 'issue_master',
  timestamps: false,
});

const Vulnerability = sequelize.define('vulnerability', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  issue_title: { type: DataTypes.STRING, allowNull: false, unique: true }
}, {
  tableName: 'vulnerabilities',
  timestamps: false,
});

async function initializeDatabase(dbName) {
  try {
    // Check if DB exists
    const [results] = await sequelize.query(
      `SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = :dbName`,
      {
        replacements: { dbName },
        type: Sequelize.QueryTypes.SELECT,
      }
    );

    if (!results) {
      await sequelize.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\``);
      logger.info(`Database '${dbName}' created.`);
    }

    await sequelize.authenticate();
    sequelize.config.database = dbName;
    await sequelize.query(`USE \`${dbName}\``);
    logger.info(`Using database '${dbName}'.`);

    await Vulnerability.sync({ force: false });
    await IssueMaster.sync({ force: false });
    logger.info('Models synchronized.');

    try {
      const existingVulns = await Vulnerability.count();
      if (existingVulns === 0) {
        await Vulnerability.bulkCreate(vulnerabilitiesList.map(title => ({ issue_title: title })));
        logger.info('Vulnerabilities seeded.');
      } else {
        logger.info('Vulnerabilities already exist.');
      }
    } catch (error) {
      logger.error(`Error checking or seeding vulnerabilities: ${error.message || error}`);

      // Try manual creation fallback
      try {
        await sequelize.query(`
          CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INT AUTO_INCREMENT PRIMARY KEY,
            issue_title VARCHAR(255) NOT NULL UNIQUE
          )
        `);
        logger.info('Vulnerabilities table created manually.');

        await Vulnerability.bulkCreate(vulnerabilitiesList.map(title => ({ issue_title: title })));
        logger.info('Vulnerabilities seeded after manual table creation.');
      } catch (err) {
        logger.error(`Failed to manually create vulnerabilities table: ${err.message || err}`);
      }
    }

  } catch (error) {
    logger.error(`Error initializing database: ${error.message || error}`);
  }
}

async function getVulnerabilities() {
  try {
    const [tableExists] = await sequelize.query(
      `SELECT COUNT(*) as count
       FROM information_schema.tables
       WHERE table_schema = :dbName
       AND table_name = 'vulnerabilities'`,
      {
        replacements: { dbName: sequelize.config.database },
        type: Sequelize.QueryTypes.SELECT,
      }
    );

    if (!tableExists || tableExists.count === 0) {
      logger.info('Vulnerabilities table does not exist, creating it now...');
      await Vulnerability.sync({ force: false });
      await Vulnerability.bulkCreate(vulnerabilitiesList.map(title => ({ issue_title: title })));
      logger.info('Vulnerabilities table created and seeded.');
    }

    const vulnerabilities = await sequelize.query(
      `SELECT issue_title FROM vulnerabilities ORDER BY id ASC`,
      {
        type: Sequelize.QueryTypes.SELECT,
      }
    );
    let arr =  vulnerabilities.map(v => v.issue_title)
    logger.log('info', `${arr}`)
    return arr;
  } catch (error) {
    logger.error(`Error fetching vulnerabilities: ${error.message || error}`);
    return [];
  }
}

module.exports = {
  sequelize,
  initializeDatabase,
  getVulnerabilities,
};
