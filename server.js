require('dotenv').config();
const express = require('express');
const app = express();
const {
    databaseExists, createDatabase, dataInjection 
} = require('./db.js');
app.use(express.json());
app.listen(process.env.PORT || 3000,async()=>{
    console.log(`Server is running on port ${process.env.PORT || 3000}`);
    await databaseExists(process.env.DB_NAME).then(async (exists) => {
        if (!exists.exists) {
            console.log(`Database ${process.env.DB_NAME} does not exist. Creating...`);
            await createDatabase(process.env.DB_NAME)
            console.log(`Database ${process.env.DB_NAME} created successfully.`);
        }
        console.log(`Database ${process.env.DB_NAME} exists.`);
        await dataInjection(process.env.DB_NAME).then(() => {
            console.log(`Data injected into ${process.env.DB_NAME} successfully.`);
        }).catch((error) => {
            console.error('Error injecting data:', error);
        });
    })
})