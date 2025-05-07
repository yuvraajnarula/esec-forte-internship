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
router.post('/submit', upload.single('file'), (req, res) => {
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
        const workbook  = xlsx.readFile(filePath);
        const sheetName = workbook.SheetNames[0];
        const sheet     = workbook.Sheets[sheetName];
        const rows = xlsx.utils.sheet_to_json(sheet, { defval: null });
        console.log('Rows:', rows);
        console.log(`Parsed ${rows.length} rows from ${origName}`);
    } catch (err) {
        console.error('Error processing spreadsheet:', err);
        res.status(500).send('Failed to process spreadsheet.');
    } finally {
        fs.unlink(filePath, unlinkErr => {
            if (unlinkErr) console.warn('Could not remove temp file', unlinkErr);
        });
    }
});

module.exports = router;