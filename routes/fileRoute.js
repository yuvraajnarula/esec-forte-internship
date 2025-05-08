const express = require('express');
const path = require('path');
const multer = require('multer');
const xlsx = require('xlsx');
const fs = require('fs');
const router = express.Router();
const upload = multer({
    dest: path.join(__dirname, '../uploads/'),
    limits: { fileSize: 20 * 1024 * 1024 },
});
const { sequelize } = require('../db.js');
router.post('/submit', upload.single('file'), async (req, res) => {
    if (!req.file) {
        console.log('NO FILE! req.file is', req.file);
        return res.status(400).send('No file uploaded.');
    }
    const origName = req.file.originalname;
    const ext = path.extname(origName).toLowerCase();
    if (!['.xlsx', '.ods'].includes(ext)) {
        fs.unlink(req.file.path, () => { });
        return res.status(400).send('Unsupported format—please upload .xlsx or .ods');
    }
    console.log('BODY:', req.body);
    console.log('FILE:', req.file);
    console.log('Original name:', req.file.originalname);
    const filePath = req.file.path;
    try {
        const workbook = xlsx.readFile(filePath, { cellDates: true });
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const jsonData = xlsx.utils.sheet_to_json(sheet);
        if (jsonData.length === 0) {
            return res.status(400).send('Uploaded file contains no data.');
        }
        console.log(`Rows found in sheet: ${jsonData.length}`);
        // MAP AND VALIDATE DATA
        const cols = Object.keys(jsonData[0]);
        console.log('Columns found in sheet:', cols);
        //use sequelize to get columns from db
        const [colFromDB] = await sequelize.query(`DESC ISSUE_MASTER`);
        const colFromDBNames = colFromDB.map((col) => col.Field);
        console.log('Columns found in DB:', colFromDBNames);
        const invalidCols = cols.filter((col) => !colFromDBNames.includes(col));
        if (invalidCols.length > 0) {
            if (invalidCols.length === cols.length) {
                const newFilePath = path.join(__dirname, '../uploads/valid_columns.ods');
                const newWorkbook = xlsx.utils.book_new();
                const newSheet = xlsx.utils.json_to_sheet([colFromDBNames]);
                xlsx.utils.book_append_sheet(newWorkbook, newSheet, 'Valid Columns');
                xlsx.writeFile(newWorkbook, newFilePath);
                return res.status(200).send(
                    'All invalid columns found. Please download the file with valid columns. <a href="/file/download/valid_columns.ods">Download</a>'
                );
            }
            return res.status(400).send(`Invalid columns found: ${invalidCols.join(', ')}`);
        }

    }
    catch (err) {
        console.error('Error converting file:', err);
        return res.status(500).send('Error converting file');
    }
    finally {
        fs.unlink(filePath, (err) => {
            if (err) {
                console.error('Error deleting file:', err);
            } else {
                console.log('File deleted successfully');
            }
        });
    }
});
const UPLOADS_DIR = 'D:\\code\\esec_forte\\esec-forte-internship\\uploads';

router.get('/download/:filename', (req, res) => {
    console.log('Uploads dir contains:', fs.readdirSync(UPLOADS_DIR));
    let filename = req.params.filename;
    if (path.extname(filename).toLowerCase() !== '.ods') {
        filename += '.ods';
    }
    const filePath = path.join(UPLOADS_DIR, filename);
    console.log('Looking for file:', filePath);
    if (fs.existsSync(filePath)) {
        return res.download(filePath, err => {
            if (err) {
                console.error('Error during download:', err);
                if (!res.headersSent) {
                    res.status(500).send('Error downloading file');
                }
            } else {
                console.log('Download started:', filename);
            }
        });
    }
    console.warn('File not found:', filePath);
    res.status(404).send('File not found');
});
module.exports = router;