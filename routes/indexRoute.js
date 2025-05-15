const express = require('express');
const { getVulnerabilities } = require('../db');
const router = express.Router();
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info', 
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} [${level.toUpperCase()}]: ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'app.log' }),
  ],
});
let vulnerabilities = [];
(async () => {
  try {
    vulnerabilities = await getVulnerabilities();
    logger.log('info', `Loaded vulnerabilities: ${vulnerabilities}`);
  } catch (error) {
    logger.error(`Failed to load vulnerabilities: ${error.message}`);
  }
})();


logger.log('info', `${vulnerabilities}`);
router.get('/', (req, res) => {
    res.render('index',{
        vulnerabilities : vulnerabilities
    });
});
module.exports = router;