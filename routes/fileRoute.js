const express = require('express');
const path = require('path');
const multer = require('multer');
const xlsx = require('xlsx');
const fs = require('fs');
const router = express.Router();

const UPLOADS_DIR = path.join(__dirname, '../uploads/');

const upload = multer({
    dest: UPLOADS_DIR,
    limits: { fileSize: 20 * 1024 * 1024 },
});
const { sequelize } = require('../db.js');

const vulnerabilities = [
    "SQL Injection (SQLi)",
    "Cross-Site Scripting (XSS)",
    "Cross-Site Request Forgery (CSRF)",
    "Broken Authentication and Session Management",
    "Insecure Direct Object References (IDOR)",
    "Security Misconfiguration",
    "Sensitive Data Exposure",
    "Using Components with Known Vulnerabilities",
    "Insecure Deserialization",
    "Insufficient Logging & Monitoring",
    "Server-Side Request Forgery (SSRF)",
    "XML External Entity (XXE) Injection",
    "Unvalidated Redirects & Forwards",
    "Privilege Escalation",
    "Business Logic Flaws",
    "API Vulnerabilities",
    "Inadequate Input Validation",
    "Weak Password Policies",
    "Unencrypted Sensitive Data at Rest",
    "Improper Error Handling",
    "Directory Traversal",
    "Clickjacking",
    "Memory Corruption (Buffer Overflows)",
    "Race Conditions",
    "Certificate & TLS Misconfigurations",
    "Open Redirects",
    "Hard-Coded Credentials",
    "Insufficient Session Expiration",
    "Client-Side Security Bypass",
    "Cloud Misconfigurations"
];  

// Helper function to add vulnerabilities sheet to a workbook
function addVulnerabilitiesSheet(workbook) {
    const vulnSheet = xlsx.utils.json_to_sheet(
        vulnerabilities.map((vulnerability, index) => ({
            'S.No': index + 1,
            'Vulnerability': vulnerability
        }))
    );
    
    const wscols = [
        { wch: 6 },
        { wch: 50 }, 
    ];
    vulnSheet['!cols'] = wscols;
    
    xlsx.utils.book_append_sheet(workbook, vulnSheet, 'Vulnerabilities');
    return workbook;
}

// Helper function to create data validation for issue_title column (column C)
function addDataValidation(sheet, rowCount) {
    if (!sheet['!validations']) {
        sheet['!validations'] = [];
    }

    // Add dropdown validation
    sheet['!validations'].push({
        sqref: `C2:C${rowCount + 1}`,
        formulas: [`Vulnerabilities!$B$2:$B$${vulnerabilities.length + 1}`],
        type: 'list',
        allowBlank: false,
        errorStyle: 'stop',
        showErrorMessage: true,
        errorTitle: 'Invalid Vulnerability',
        error: 'Please select a vulnerability from the dropdown list. Only predefined vulnerabilities are allowed.',
        showDropdown: true,
        promptTitle: 'Select Vulnerability',
        prompt: 'Choose a vulnerability from the predefined list'
    });

    // Set column protection to prevent free text entry
    if (!sheet['!protect']) {
        sheet['!protect'] = {
            password: '',
            formatCells: true,
            formatColumns: true,
            formatRows: true,
            insertColumns: true,
            insertRows: true,
            insertHyperlinks: true,
            deleteColumns: true,
            deleteRows: true,
            sort: true,
            autoFilter: true,
            pivotTables: true
        };
    }

    return sheet;
}

// Helper function to safely download a file
function downloadFile(filename, rows) {
    try {
        const name = path.basename(filename);
        const safeFilename = name.replace(/[^a-zA-Z0-9_.-]/g, '_');
        const now = new Date();
        const timestamp = `${now.getMinutes()}_${now.getSeconds()}`;
        const filenameWithTimestamp = `${safeFilename.replace(/\.xlsx$/, '')}_${timestamp}.ods`;
        
        const newName = path.join(UPLOADS_DIR, filenameWithTimestamp);
        
        const colHeaders = [
            'issue_master_id',
            'issue_master_key', 'issue_title', 'description', 'impact',
            'recommendation', 'owasp_ref_no', 'cwe_cve_ref_no',
            'appl_type', 'audit_methodology_type', 'created_by_id',
            'created_on', 'is_updated', 'updated_by_user',
            'deleted_on'
        ];
        
        const newWorkbook = xlsx.utils.book_new();
        const newSheet = xlsx.utils.json_to_sheet(rows, { header: colHeaders });

        // Add data validation on issue_title column
        addDataValidation(newSheet, rows.length);
        
        const wscols = [
            { wch: 15 }, // issue_master_id
            { wch: 15 }, // issue_master_key
            { wch: 40 }, // issue_title
            { wch: 50 }, // description
            { wch: 30 }, // impact
            { wch: 30 }, // recommendation
            { wch: 15 }, // owasp_ref_no
            { wch: 15 }, // cwe_cve_ref_no
            { wch: 10 }, // appl_type
            { wch: 20 }, // audit_methodology_type
            { wch: 15 }, // created_by_id
            { wch: 20 }, // created_on
            { wch: 10 }, // is_updated
            { wch: 15 }, // updated_by_user
            { wch: 20 }  // deleted_on
        ];
        newSheet['!cols'] = wscols;
        
        xlsx.utils.book_append_sheet(newWorkbook, newSheet, 'Valid Rows');
        
        // Also add the vulnerabilities list for reference
        addVulnerabilitiesSheet(newWorkbook);
        
        xlsx.writeFile(newWorkbook, newName);
        
        return {
            downloadName: path.basename(newName),
            filePath: newName
        };
    } catch (err) {
        console.error('Error creating download file:', err);
        throw new Error(`Failed to create download file: ${err.message}`);
    }
}

// Helper function to check if a vulnerability is valid
function isValidVulnerability(title) {
    return vulnerabilities.some(vulnerability => 
        title.trim().toLowerCase() === vulnerability.toLowerCase()
    );
}

router.post('/submit', upload.single('file'), async (req, res) => {
    let tempFilePath = null;
    
    try {
        if (!req.file) {
            return res.status(400).send('No file uploaded.');
        }

        const MAX_FILE_SIZE = 20 * 1024 * 1024; // 20MB
        if (req.file.size > MAX_FILE_SIZE) {
            return res.status(400).send('File size exceeds 20MB limit');
        }

        tempFilePath = req.file.path;
        const origName = req.file.originalname;
        const ext = path.extname(origName).toLowerCase();
        
        if (!['.xlsx', '.ods'].includes(ext)) {
            return res.status(400).send('Unsupported format—please upload .xlsx or .ods');
        }

        let workbook;
        try {
            workbook = xlsx.readFile(tempFilePath, { cellDates: true });
        } catch (error) {
            return res.status(400).send(`Error reading file: ${error.message}`);
        }

        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const jsonData = xlsx.utils.sheet_to_json(sheet);

        if (jsonData.length === 0) {
            return res.status(400).send('Uploaded file contains no data.');
        }

        const [colFromDB] = await sequelize.query('DESC ISSUE_MASTER')
            .catch(err => {
                throw new Error(`Database error: ${err.message}`);
            });
            
        const colFromDBNames = colFromDB.map(col => col.Field);
        const spreadsheetCols = Object.keys(jsonData[0]);
        
        const invalidCols = spreadsheetCols.filter(col => !colFromDBNames.includes(col));
        const missingRequiredCols = ['issue_title', 'description', 'appl_type', 'audit_methodology_type']
            .filter(required => !spreadsheetCols.includes(required));
        
        if (invalidCols.length > 0 || missingRequiredCols.length > 0) {
            let message = '';
            if (invalidCols.length > 0) {
                message += `Invalid columns found: ${invalidCols.join(', ')}. `;
            }
            
            if (missingRequiredCols.length > 0) {
                message += `Missing required columns: ${missingRequiredCols.join(', ')}. `;
            }
            
            const templateFilename = 'template_issue_master.ods';
            const newFilePath = path.join(UPLOADS_DIR, templateFilename);

            const newWorkbook = xlsx.utils.book_new();
            const sampleRow = {};
            colFromDBNames.forEach(col => {
                switch(col) {
                    case 'issue_master_id':
                        sampleRow[col] = 'Auto-generated';
                        break;
                    case 'issue_title':
                        sampleRow[col] = 'Cross-Site Scripting (XSS)';  
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
            
            const templateData = [sampleRow];
            const newSheet = xlsx.utils.json_to_sheet(templateData);
            
            const wscols = [
                { wch: 15 }, // issue_master_id
                { wch: 40 }, // issue_title
                { wch: 50 }, // description
                { wch: 30 }, // impact
                { wch: 30 }, // recommendation
                { wch: 15 }, // owasp_ref_no
                { wch: 15 }, // cwe_cve_ref_no
                { wch: 10 }, // appl_type
                { wch: 20 }, // audit_methodology_type
                { wch: 15 }, // created_by_id
                { wch: 20 }, // created_on
                { wch: 10 }, // is_updated
                { wch: 15 }, // updated_by_user
                { wch: 20 }  // deleted_on
            ];
            newSheet['!cols'] = wscols;
            
            addDataValidation(newSheet, templateData.length);
            
            xlsx.utils.book_append_sheet(newWorkbook, newSheet, 'Template');
            
            addVulnerabilitiesSheet(newWorkbook);
            
            xlsx.writeFile(newWorkbook, newFilePath);

            return res.status(400).send(
                `${message} Please download the template file with valid columns. 
                <a href="/file/download/${encodeURIComponent(templateFilename)}">Download Template</a>`
            );
        }        
        const validRows = [];
        const invalidRows = [];
        jsonData.forEach((row, index) => {
            const rowNum = index + 2; 
            const errors = [];
            if (!row.issue_title) errors.push('Missing issue_title');
            if (!row.description) errors.push('Missing description');
            if (row.issue_title && row.issue_title.length > 300) 
                errors.push('issue_title exceeds 300 character limit');
            
            if (row.issue_title && !isValidVulnerability(row.issue_title)) {
                errors.push('issue_title must exactly match one of the predefined vulnerabilities');
            }
                
            const processedRow = {
                ...row,
                appl_type: row.appl_type || -1,
                audit_methodology_type: row.audit_methodology_type || 200,
                created_by_id: req.body.userId || 1,
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
        if (invalidRows.length > 0) {
            const errorReport = invalidRows.map(row => 
                `Row ${row.rowNum}: ${row.errors.join(', ')}`
            ).join('\n');
            
            return res.status(400).send(`
                Found ${invalidRows.length} rows with errors. Please fix them and try again.
                <pre>${errorReport}</pre>
            `);
        }        
        if (validRows.length > 0) {
            const lenientPatterns = vulnerabilities.map(vul => {
                const escaped = vul.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
                return escaped.replace(/\s+/g, '\\s*');
            });
            const lenientRegex = new RegExp(lenientPatterns.join('|'), 'i');
            let rowsToInsert = validRows.filter(row => lenientRegex.test(row.issue_title));
            console.log('Rows to insert:', rowsToInsert.length);
            
            if (rowsToInsert.length === 0) {
                return res.status(400).send('No valid data found to import.');
            }
            
            try {
                const { downloadName, filePath } = downloadFile(origName, rowsToInsert);
                await batchInsert(rowsToInsert);
                console.log('Rows inserted successfully:', rowsToInsert.length);
                res.render('preview', {
                    rows: rowsToInsert,
                    totalRows: validRows,
                    filename: req.file.originalname,
                    downloadName
                });
            } catch (err) {
                console.error('Error preparing file:', err);
                return res.status(500).send(`Error preparing file: ${err.message}`);
            }
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

async function batchInsert(rows) {
    const transaction = await sequelize.transaction();
    try {
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
                    ) VALUES ${batch.map(() => '(?)').join(', ')}`,
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
        
        await transaction.commit();
        return insertedCount;
    } catch (error) {
        await transaction.rollback();
        throw error;
    }
}

router.get('/download/:filename', (req, res) => {
    const filename = req.params.filename;
    const sanitizedFilename = path.basename(filename);
    const filePath = path.join(UPLOADS_DIR, sanitizedFilename);
    
    console.log('Looking for file:', filePath);

    if (!fs.existsSync(filePath)) {
        console.warn('File not found:', filePath);
        return res.status(404).send('File not found');
    }

    const fileStream = fs.createReadStream(filePath);

    // Handle stream errors
    fileStream.on('error', (err) => {
        console.error('Stream error:', err);
        if (!res.headersSent) {
            res.status(500).send('Error streaming file');
        }
    });

    req.on('close', () => {
        fileStream.destroy();
        console.log('Download aborted by client');
    });

    res.download(filePath, sanitizedFilename, (err) => {
        if (err) {
            console.error('Error during download:', err);
            if (!res.headersSent) {
                res.status(500).send('Error downloading file');
            }
        } else {
            console.log('Download completed:', sanitizedFilename);
        }
    });
});

router.get('/preview', (req, res) => {
    try {
        let { filename, rows, totalRows } = req.body || req.query;

        if (!filename || !rows) {
            return res.status(400).send('Missing filename or rows in request.');
        }        
        if (typeof rows === 'string') {
            rows = JSON.parse(rows);
        }
        
        if (totalRows && typeof totalRows === 'string') {
            totalRows = JSON.parse(totalRows);
        } else {
            totalRows = [];
        }
        const { downloadName } = downloadFile(filename, rows);
        
        res.render('preview', {
            rows,
            totalRows,
            filename,
            downloadName
        });
    } catch (err) {
        console.error('Error in /preview:', err);
        res.status(500).send(`Preview generation failed: ${err.message}`);
    }
});

module.exports = router;