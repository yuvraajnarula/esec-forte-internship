require('dotenv').config();
const { Sequelize, DataTypes } = require('sequelize');
const winston = require('winston');
const fs = require('fs');

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
  created_on: DataTypes.DATE,
  updated_on: DataTypes.DATE,
  // Fix: ENUM values in MySQL need proper quoting
  is_updated: { 
    type: DataTypes.ENUM('1', '0'), 
    defaultValue: '0'  // Note the quotes, this was the issue
  },
  updated_by_user: { 
    type: DataTypes.ENUM('yes', 'no'), 
    defaultValue: 'no' 
  },
  deleted_on: DataTypes.DATE,
}, {
  tableName: 'issue_master',
  timestamps: false,
});

const Vulnerability = sequelize.define('vulnerability', {
  vul_id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    allowNull: false,
    primaryKey: true
  },
  app_id: {
    type: DataTypes.INTEGER,
    allowNull: false,
  },
  vul_title: {
    type: DataTypes.STRING(100),
    allowNull: false,
  },
  affected_url: {
    type: DataTypes.TEXT,
  },
  risk_rating: {
    type: DataTypes.STRING(50),
    defaultValue: null,
  },
  affected_parameters: {
    type: DataTypes.TEXT
  },
  description: {
    type: DataTypes.TEXT
  },
  impact: {
    type: DataTypes.TEXT
  },
  recommendation: {
    type: DataTypes.TEXT
  },
  reference: {
    type: DataTypes.TEXT
  },
  status: {
    type: DataTypes.STRING(50),
    defaultValue: null,
  },
  created_on: {
    type: DataTypes.DATE,
    allowNull: false,
  },
  updated_on: {
    type: DataTypes.DATE,
    defaultValue: null,
  },
  deleted_on: {
    type: DataTypes.DATE,
    defaultValue: null,
  },
}, {
  tableName: 'vulnerabilities',
  timestamps: false,
  charset: 'utf8mb3',
  collate: 'utf8mb3_general_ci'
});

async function initializeDatabase(dbName) {
  try {
    // Add better error handling and logging
    logger.info(`Attempting to initialize database: ${dbName}`);
    
    // Check if database exists
    const [res] = await sequelize.query(
      `SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = :dbName`,
      {
        replacements: { dbName },
        type: Sequelize.QueryTypes.SELECT,
      }
    );
    
    if (!res) {
      logger.info(`Database '${dbName}' doesn't exist, creating it...`);
      await sequelize.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\``);
      logger.info(`Database '${dbName}' created`);
    } else {
      logger.info(`Database '${dbName}' already exists`);
    }
    
    // Test connection
    await sequelize.authenticate();
    logger.info('Database connection established successfully.');
    
    // Set the database to use
    sequelize.config.database = dbName;
    await sequelize.query(`USE \`${dbName}\``);
    logger.info(`Using database ${dbName}`);
    
    // Check if tables exist before synchronizing
    const [issueTableExists] = await sequelize.query(
      `SELECT COUNT(*) as count
       FROM information_schema.tables
       WHERE table_schema = :dbName
       AND table_name = 'issue_master'`,
      {
        replacements: { dbName },
        type: Sequelize.QueryTypes.SELECT,
      }
    );
    
    if (!issueTableExists || issueTableExists.count === 0) {
      logger.info('Issue Master table does not exist, creating it...');
      await IssueMaster.sync({ force: false });
      logger.info('Issue Master table created');
    } else {
      logger.info('Issue Master table already exists');
    }
    
    const [vulnTableExists] = await sequelize.query(
      `SELECT COUNT(*) as count
       FROM information_schema.tables
       WHERE table_schema = :dbName
       AND table_name = 'vulnerabilities'`,
      {
        replacements: { dbName },
        type: Sequelize.QueryTypes.SELECT,
      }
    );
    
    if (!vulnTableExists || vulnTableExists.count === 0) {
      logger.info('Vulnerabilities table does not exist, creating it...');
      await Vulnerability.sync({ force: false });
      logger.info('Vulnerabilities table created');
    } else {
      logger.info('Vulnerabilities table already exists');
    }
    
    // Check if data needs to be seeded
    try {
      const existingVuln = await IssueMaster.count();
      if (existingVuln === 0) {
        logger.info('No issues found in Issue Master, seeding data...');
        await seedingIssueMaster();
        logger.info('Issue Master table seeded successfully');
      } else {
        logger.info(`Found ${existingVuln} existing issues, skipping seeding`);
      }
    } catch (error) {
      logger.error(`Error checking or seeding vulnerabilities: ${error.message || error}`);
      
      // Attempt manual table creation if necessary
      try {
        logger.info('Attempting manual table creation for issue_master...');
        await sequelize.query(`
          CREATE TABLE IF NOT EXISTS issue_master (
            issue_master_id INT NOT NULL AUTO_INCREMENT,
            issue_master_key VARCHAR(255),
            issue_title VARCHAR(255) NOT NULL UNIQUE,
            description TEXT,
            impact TEXT,
            recommendation TEXT,
            owasp_ref_no VARCHAR(255),
            cwe_cve_ref_no VARCHAR(255),
            appl_type INT DEFAULT -1,
            audit_methodology_type INT DEFAULT 200,
            created_on DATETIME,
            updated_on DATETIME,
            is_updated ENUM('1', '0') DEFAULT '0',
            updated_by_user ENUM('yes', 'no') DEFAULT 'no',
            deleted_on DATETIME,
            PRIMARY KEY (issue_master_id)
          ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;
        `);
        logger.info('Issue Master table created manually');
        await seedingIssueMaster();
        logger.info('Issue Master table seeded');
      } catch (err) {
        logger.error(`Failed to manually create issue_master table: ${err.message || err}`);
      }
      
      try {
        logger.info('Attempting manual table creation for vulnerabilities...');
        await sequelize.query(`
          CREATE TABLE IF NOT EXISTS vulnerabilities (
            vul_id INT NOT NULL AUTO_INCREMENT,
            app_id INT NOT NULL,
            vul_title VARCHAR(100) NOT NULL,
            affected_url TEXT,
            risk_rating VARCHAR(50) DEFAULT NULL,
            affected_parameters TEXT,
            description TEXT,
            impact TEXT,
            recommendation TEXT,
            reference TEXT,
            status VARCHAR(50) DEFAULT NULL,
            created_on DATETIME NOT NULL,
            updated_on DATETIME DEFAULT NULL,
            deleted_on DATETIME DEFAULT NULL,
            PRIMARY KEY (vul_id)
          ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
        `);
        logger.info('Vulnerabilities table created manually');
      } catch (err) {
        logger.error(`Failed to manually create vulnerabilities table: ${err.message || err}`);
      }
    }
    
    logger.info('Database initialization completed successfully');
    return true;
  } catch (error) {
    logger.error(`Error initializing database: ${error.message || error}`);
    // Provide more detailed error information
    if (error.parent) {
      logger.error(`SQL Error: ${error.parent.code} - ${error.parent.sqlMessage}`);
    }
    return false;
  }
}

async function seedingIssueMaster() {
  let transaction;
  try {
    logger.info('Starting Issue Master seeding process');
    transaction = await sequelize.transaction();
    
    // Verify that the file exists before trying to read it
    if (!fs.existsSync('vulnerability_issues.json')) {
      throw new Error('vulnerability_issues.json file not found');
    }
    
    const data = await fs.promises.readFile('vulnerability_issues.json', 'utf-8');
    const JSONdata = JSON.parse(data);
    
    logger.info(`Found ${JSONdata.length} issues to seed`);
    
    for (const vuln of JSONdata) {
      // Added validation to ensure data consistency
      const issueTitle = vuln.issue_title || "";
      if (!issueTitle) {
        logger.warn('Skipping record with empty issue_title');
        continue;
      }
      
      const dataArr = [
        vuln.issue_master_key || null,
        issueTitle,
        vuln.description || null,
        vuln.impact || null,
        vuln.recommendation || null,
        vuln.owasp_ref_no || null,
        vuln.cwe_cve_ref_no || null,
        vuln.appl_type || -1,
        vuln.audit_methodology_type || 200,
        vuln.created_on && !isNaN(new Date(vuln.created_on))
          ? new Date(vuln.created_on)
          : new Date(), // Default to current date
        vuln.updated_on && !isNaN(new Date(vuln.updated_on))
          ? new Date(vuln.updated_on)
          : null, 
        vuln.is_updated || '0', // Use string value for ENUM
        vuln.updated_by_user || 'no', // Use string value for ENUM
        vuln.deleted_on && !isNaN(new Date(vuln.deleted_on))
          ? new Date(vuln.deleted_on)
          : null,
      ];
      
      await sequelize.query(
        `
        INSERT INTO issue_master(
          issue_master_key,
          issue_title,
          description,
          impact,
          recommendation,
          owasp_ref_no,
          cwe_cve_ref_no,
          appl_type,
          audit_methodology_type,
          created_on,
          updated_on,
          is_updated,
          updated_by_user,
          deleted_on
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        {
          replacements: dataArr,
          type: sequelize.QueryTypes.INSERT,
          transaction
        }
      );
    }
    
    await transaction.commit();
    logger.info('Issue Master seeding completed successfully');
  } catch (error) {
    if (transaction) await transaction.rollback();
    logger.error(`Error seeding Issue Master: ${error.message || error}`);
    throw error; // Re-throw to allow calling function to handle
  }
}

async function getVulnerabilities() {
  try {
    logger.info('Fetching vulnerabilities from database');
    
    // Check if table exists before querying
    const [tableExists] = await sequelize.query(
      `SELECT COUNT(*) as count
       FROM information_schema.tables
       WHERE table_schema = :dbName
       AND table_name = 'issue_master'`,
      {
        replacements: { dbName: sequelize.config.database },
        type: Sequelize.QueryTypes.SELECT,
      }
    );
    
    if (!tableExists || tableExists.count === 0) {
      logger.info('issue_master table does not exist, creating it now...');
      await IssueMaster.sync({ force: false });
      logger.info('Issue Master table created');
      
      // Check if we need to seed
      const count = await IssueMaster.count();
      if (count === 0) {
        logger.info('Seeding Issue Master with initial data');
        await seedingIssueMaster();
        logger.info('Issue Master table seeded');
      }
    }
    
    // Query vulnerabilities
    const vulnerabilities = await sequelize.query(
      `SELECT issue_title FROM issue_master ORDER BY issue_master_id ASC`, 
      {
        type: Sequelize.QueryTypes.SELECT,
      }
    );
    
    const arr = vulnerabilities.map(v => v.issue_title);
    logger.info(`Retrieved ${arr.length} vulnerabilities`);
    logger.info(`Vulnerabilities: ${arr.join(', ')}`);
    
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
  IssueMaster,
  Vulnerability
};