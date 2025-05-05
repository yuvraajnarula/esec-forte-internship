require('dotenv').config();
const { Sequelize } = require('sequelize');
const { faker } = require('@faker-js/faker');
const path = require('path');
const fs = require('fs');
const csv = require('csv-parse/sync'); // Add this at the top with other requires
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
            CREATE TABLE IF NOT EXISTS products (
                id INT AUTO_INCREMENT PRIMARY KEY,
                productName VARCHAR(255) NOT NULL,
                productBrand VARCHAR(255) NOT NULL,
                price FLOAT NOT NULL CHECK (price > 0),
                description TEXT,
                imageUrl VARCHAR(255),
                category VARCHAR(255),
                stock INT DEFAULT 0 CHECK (stock >= 0),
                rating FLOAT DEFAULT 0 CHECK (rating >= 0 AND rating <= 5),
                createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `);
        console.log(`Table 'products' created successfully.`);
        const [countResult] = await sequelize.query(
            `SELECT COUNT(*) as count FROM products`,
            {
                type: Sequelize.QueryTypes.SELECT
            }
        );
        if (countResult.count > 0) {
            console.log('Table "products" already contains data. Skipping data injection.');
            return;
        }

        const dataEntries = [];
        let i = 0;
        // read csv file and parse it for data injection
        const csvFilePath = path.join(__dirname, 'amazon-products.csv');
        const csvFile = fs.readFileSync(csvFilePath, 'utf8');
        const records = csv.parse(csvFile, {
            columns: true,
            skip_empty_lines: true,
            relax_quotes: true,
            trim: true
        });

        for (const record of records) {
            let recordPrice = record.actual_price.replace(',', '');
            recordPrice = recordPrice.replace('₹', '');
            let data = {
                productName: record.sub_category || 'Unknown',
                productBrand: record.name?.split(' ')[0] || 'Unknown',
                price: parseFloat(recordPrice) || faker.commerce.price({ min: 100 }),
                description: record.name || '',
                imageUrl: record.image || '',
                category: record.main_category || 'Uncategorized',
                stock: Math.floor(Math.random() * 1000),
                rating: parseFloat(record.ratings) || faker.number.float({ min: 1, max: 5, fractionDigits: 1 }),
                createdAt: faker.date.past(),
                updatedAt: new Date()
            }
            dataEntries.push(data);
        }

        for (let i = 0; i < dataEntries.length; i += BATCH_SIZE) {
            const batch = dataEntries.slice(i, i + BATCH_SIZE);
            const values = batch.map(entry => `(
                ${sequelize.escape(entry.productName)},
                ${sequelize.escape(entry.productBrand)},
                ${entry.price},
                ${sequelize.escape(entry.description)},
                ${sequelize.escape(entry.imageUrl)},
                ${sequelize.escape(entry.category)},
                ${entry.stock},
                ${entry.rating},
                '${entry.createdAt.toISOString().slice(0, 19).replace('T', ' ')}',
                '${entry.updatedAt.toISOString().slice(0, 19).replace('T', ' ')}'
            )`).join(',');

            await sequelize.query(`
                INSERT INTO products (
                    productName,
                    productBrand,
                    price,
                    description,
                    imageUrl,
                    category,
                    stock,
                    rating,
                    createdAt,
                    updatedAt
                ) VALUES ${values}
            `);
            console.log(`Batch ${Math.floor(i / BATCH_SIZE) + 1} inserted (${batch.length} rows).`);
        }
        console.log(`All rows inserted successfully.`);
    } catch (error) {
        console.error('Error during data injection:', error);
    } 
}

module.exports = { sequelize, databaseExists, createDatabase, dataInjection };