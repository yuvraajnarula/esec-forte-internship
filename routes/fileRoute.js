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
    let tempFilePath = null;
    
    try {
        if (!req.file) {
            return res.status(400).send('No file uploaded.');
        }

        tempFilePath = req.file.path;
        const origName = req.file.originalname;
        const ext = path.extname(origName).toLowerCase();
        
        if (!['.xlsx', '.ods'].includes(ext)) {
            return res.status(400).send('Unsupported format—please upload .xlsx or .ods');
        }

        const workbook = xlsx.readFile(tempFilePath, { cellDates: true });
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const jsonData = xlsx.utils.sheet_to_json(sheet);

        if (jsonData.length === 0) {
            return res.status(400).send('Uploaded file contains no data.');
        }

        // Get database columns
        const [colFromDB] = await sequelize.query('DESC ISSUE_MASTER')
            .catch(err => {
                throw new Error(`Database error: ${err.message}`);
            });
            
        const colFromDBNames = colFromDB.map(col => col.Field);
        const spreadsheetCols = Object.keys(jsonData[0]);
        
        // FIX: Define invalidCols variable to find columns in spreadsheet not in DB
        const invalidCols = spreadsheetCols.filter(col => !colFromDBNames.includes(col));
        const missingRequiredCols = ['issue_title', 'description', 'appl_type', 'audit_methodology_type']
            .filter(required => !spreadsheetCols.includes(required));
        
        // Handle invalid or missing columns
        if (invalidCols.length > 0 || missingRequiredCols.length > 0) {
            let message = '';
            if (invalidCols.length > 0) {
                message += `Invalid columns found: ${invalidCols.join(', ')}. `;
            }
            
            if (missingRequiredCols.length > 0) {
                message += `Missing required columns: ${missingRequiredCols.join(', ')}. `;
            }
            
            const newFilePath = path.join(__dirname, '../uploads', 'template_issue_master.ods');

            const newWorkbook = xlsx.utils.book_new();
            // Create a sample row with all required fields
            const sampleRow = {};
            colFromDBNames.forEach(col => {
                // Set default sample values based on column type
                switch(col) {
                    case 'issue_master_id':
                        sampleRow[col] = 'Auto-generated';
                        break;
                    case 'issue_title':
                        sampleRow[col] = 'Example Security Issue Title';
                        break;
                    case 'description':
                        sampleRow[col] = 'Detailed description of the security issue';
                        break;
                    case 'impact':
                        sampleRow[col] = 'Potential impact of the vulnerability';
                        break;
                    case 'recommendation':
                        sampleRow[col] = 'Recommendations to fix the issue';
                        break;
                    case 'appl_type':
                        sampleRow[col] = '1';
                        break;
                    case 'audit_methodology_type':
                        sampleRow[col] = '200';
                        break;
                    case 'created_by_id':
                        sampleRow[col] = '1';
                        break;
                    case 'created_on':
                        sampleRow[col] = new Date().toISOString();
                        break;
                    default:
                        sampleRow[col] = '';
                }
            });
            
            // Create template with column names and sample row
            const templateData = [sampleRow];
            const newSheet = xlsx.utils.json_to_sheet(templateData);
            
            xlsx.utils.book_append_sheet(newWorkbook, newSheet, 'Template');
            xlsx.writeFile(newWorkbook, newFilePath);

            return res.status(400).send(
                `${message} Please download the template file with valid columns. 
                <a href="/file/download/${path.basename(newFilePath)}">Download Template</a>`
            );
        }
        
        // FIX: Implement actual data import to database
        const validRows = [];
        const invalidRows = [];
        
        // Validate each row and prepare for import
        jsonData.forEach((row, index) => {
            // Track row number for error reporting
            const rowNum = index + 2; 
            const errors = [];
            
            // Check required fields
            if (!row.issue_title) errors.push('Missing issue_title');
            if (!row.description) errors.push('Missing description');
            if (row.issue_title && row.issue_title.length > 300) 
                errors.push('issue_title exceeds 300 character limit');
                
            // Set default values for fields that need them
            const processedRow = {
                ...row,
                appl_type: row.appl_type || -1,
                audit_methodology_type: row.audit_methodology_type || 200,
                created_by_id: req.body.userId || 1, // Assuming user ID is passed in the request
                created_on: new Date(),
                is_updated: '0',
                updated_by_user: 'no'
            };
            
            if (errors.length === 0) {
                validRows.push(processedRow);
            } else {
                invalidRows.push({
                    rowNum,
                    data: row,
                    errors
                });
            }
        });
        
        // If there are invalid rows, generate report and stop
        if (invalidRows.length > 0) {
            const errorReport = invalidRows.map(row => 
                `Row ${row.rowNum}: ${row.errors.join(', ')}`
            ).join('\n');
            
            return res.status(400).send(`
                Found ${invalidRows.length} rows with errors. Please fix them and try again.
                <pre>${errorReport}</pre>
            `);
        }
        
        // If all rows are valid, insert into database
        if (validRows.length > 0) {
            const insertCount = await batchInsert(validRows);
            return res.status(200).send(`
                File processed successfully. 
                Imported ${insertCount} records into the database.
            `);
        } else {
            return res.status(400).send('No valid data found to import.');
        }

    } catch (err) {
        console.error('Error processing file:', err);
        return res.status(500).send(`Error processing file: ${err.message}`);
    } finally {
        if (tempFilePath) {
            fs.unlink(tempFilePath, err => {
                if (err) console.error('Error deleting temporary file:', err);
            });
        }
    }
});

// Helper function to insert data in batches for better performance
async function batchInsert(rows) {
    const BATCH_SIZE = 100;
    let insertedCount = 0;
    
    for (let i = 0; i < rows.length; i += BATCH_SIZE) {
        const batch = rows.slice(i, i + BATCH_SIZE);
        try {
            await sequelize.query(
                `INSERT INTO issue_master (
                    issue_master_key, issue_title, description, impact, 
                    recommendation, owasp_ref_no, cwe_cve_ref_no, 
                    appl_type, audit_methodology_type, created_by_id, 
                    created_on, is_updated, updated_by_user
                ) VALUES ${batch.map(row => '(?)').join(', ')}`,
                {
                    replacements: batch.map(row => [
                        row.issue_master_key || null,
                        row.issue_title,
                        row.description,
                        row.impact || null,
                        row.recommendation || null,
                        row.owasp_ref_no || null,
                        row.cwe_cve_ref_no || null,
                        row.appl_type,
                        row.audit_methodology_type,
                        row.created_by_id,
                        row.created_on,
                        row.is_updated,
                        row.updated_by_user
                    ]),
                    type: sequelize.QueryTypes.INSERT
                }
            );
            insertedCount += batch.length;
        } catch (error) {
            console.error('Error during batch insert:', error);
            throw new Error(`Failed to insert batch starting at row ${i+1}: ${error.message}`);
        }
    }
    
    return insertedCount;
}

const UPLOADS_DIR = path.join(__dirname, '../uploads');

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