require('dotenv').config();
const express = require('express');
const { databaseExists, createDatabase, dataInjection } = require('../db');
const router = express.Router();

router.get('/exists/:dbName', async (req, res) => {
    const { dbName } = req.params;
    try {
        const exists = await databaseExists(dbName);

        if (!exists) {
            console.log(`Database '${dbName}' does not exist. Creating and injecting data...`);
            await createDatabase(dbName);
            await dataInjection(dbName);
            return res.status(200).json({ message: `Database '${dbName}' created and populated.` });
        } else {
            console.log(`Database '${dbName}' already exists.`);
            await dataInjection(dbName);
            return res.status(200).json({ message: `Database '${dbName}' already exists. Data injected.` });
        }

    } catch (error) {
        console.error('Error checking database existence:', error);
        return res.status(500).json({ error: `Internal server error: ${error.message}` });
    }
});

module.exports = router;