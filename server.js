require('dotenv').config();
const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const winston = require('winston');

const { initializeDatabase } = require('./db.js');
const indexRoute = require('./routes/indexRoute.js');
const fileRoute = require('./routes/fileRoute.js');

const PORT = process.env.PORT || 3001;
const app = express();

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
    new winston.transports.File({ filename: 'combined.log' })
  ],
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.use(expressLayouts);
app.use(express.static('public'));

app.use('/', indexRoute);
app.use('/file', fileRoute);

(async () => {
  try {
    await initializeDatabase(process.env.DB_NAME);
    logger.info('Database initialized successfully.');
    const server = app.listen(PORT, '127.0.0.1', () => {
      logger.info(`Server is running on port ${PORT}`);
      logger.info(`address() = ${JSON.stringify(server.address())}`);
    });

    server.on('error', (err) => {
      logger.error(`Listen error: ${err.message}`);
    });
  } catch (error) {
    logger.error(`Error during server startup: ${error.message || error}`);
    process.exit(1);
  }
})();
