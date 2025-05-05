require('dotenv').config();
const express = require('express');
const app = express();
const dbRoutes = require('./routes/dbOps');

app.use('/api/db', dbRoutes);
app.listen(process.env.PORT || 3000,()=>{
    console.log(`Server is running on port ${process.env.PORT || 3000}`);
})