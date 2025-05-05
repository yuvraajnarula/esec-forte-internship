require('dotenv').config();
const { Sequelize } = require('sequelize');
const { faker } = require('@faker-js/faker');

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

        // Check if table already has records
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
        for (let i = 0; i < rows; i++) {
            dataEntries.push({
                productName: faker.commerce.productName(),
                productBrand: faker.company.name(),
                price: faker.commerce.price({ min: 100 }),
                // description: faker.commerce.productDescription(),
                imageUrl: faker.image.urlLoremFlickr({
                    category: faker.commerce.product(),
                    width: 640,
                    height: 480,
                    count: 1,
                }),
                category: faker.commerce.product(),
                stock: faker.number.int({ min: 0, max: 100 }),
                rating: faker.number.float({ min: 0, max: 5, fractionDigits: 1 }),
                createdAt: faker.date.past(),
                updatedAt: faker.date.recent(),
            });
        }
        console.log(`Generated ${rows} fake product entries.`);

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