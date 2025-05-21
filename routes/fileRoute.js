const express = require('express');
const path = require('path');
const multer = require('multer');
const ExcelJS = require('exceljs');
const fs = require('fs');
const router = express.Router();
const winston = require('winston');
const { exec } = require('child_process');

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'app.log' }),
    ],
});

const UPLOADS_DIR = path.join(__dirname, '../uploads/');

const upload = multer({
    dest: UPLOADS_DIR,
    limits: { fileSize: 20 * 1024 * 1024 },
});
const { sequelize, getVulnerabilities } = require('../db.js');
const { log } = require('console');

let vulnerabilities = [];
(async () => {
    try {
        vulnerabilities = await getVulnerabilities();
        logger.log('info', `Loaded vulnerabilities: ${vulnerabilities}`);
    } catch (error) {
        logger.error(`39 - Failed to load vulnerabilities: ${error.message}`);
    }
})();

function addVulnerabilitiesSheet(workbook) {
    const vulnSheet = workbook.addWorksheet('Vulnerabilities');

    // Add headers
    vulnSheet.columns = [
        { header: 'S.No', key: 'sno', width: 6 },
        { header: 'Vulnerability', key: 'vulnerability', width: 50 }
    ];
    const vulnData = vulnerabilities.map((vulnerability, index) => ({
        sno: index + 1,
        vulnerability: vulnerability
    }));

    vulnSheet.addRows(vulnData);

    // Format header row
    const headerRow = vulnSheet.getRow(1);
    headerRow.font = { bold: true };

    headerRow.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFD3D3D3' }
    };

    return workbook;
}

// Helper function to safely download a file
async function downloadFile(filename, rows) {
    try {
        const name = path.basename(filename);
        const safeFilename = name.replace(/[^a-zA-Z0-9_.-]/g, '_');
        const now = new Date();
        const timestamp = `${now.getMinutes()}_${now.getSeconds()}`;
        const filenameBase = `${safeFilename.replace(/\.(xlsx|ods)$/, '')}_${timestamp}`;

        const xlsxName = path.join(UPLOADS_DIR, `${filenameBase}.xlsx`);

        // Updated columns for vulnerabilities table structure
        const colHeaders = [
            'vul_id', 'app_id', 'vul_title', 'affected_url', 'risk_rating',
            'affected_parameters', 'description', 'impact',
            'recommendation', 'reference', 'status',
            'created_on', 'updated_on', 'deleted_on'
        ];

        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Valid Rows');

        // Define columns for vulnerabilities structure
        worksheet.columns = [
            { header: 'vul_id', key: 'vul_id', width: 10 },
            { header: 'app_id', key: 'app_id', width: 10 },
            { header: 'vul_title', key: 'vul_title', width: 40 },
            { header: 'affected_url', key: 'affected_url', width: 50 },
            { header: 'risk_rating', key: 'risk_rating', width: 15 },
            { header: 'affected_parameters', key: 'affected_parameters', width: 30 },
            { header: 'description', key: 'description', width: 50 },
            { header: 'impact', key: 'impact', width: 30 },
            { header: 'recommendation', key: 'recommendation', width: 30 },
            { header: 'reference', key: 'reference', width: 30 },
            { header: 'status', key: 'status', width: 15 },
            { header: 'created_on', key: 'created_on', width: 15 },
            { header: 'updated_on', key: 'updated_on', width: 15 },
            { header: 'deleted_on', key: 'deleted_on', width: 15 }
        ];

        // Format header row
        const headerRow = worksheet.getRow(1);
        headerRow.font = { bold: true };
        headerRow.fill = {
            type: 'pattern',
            pattern: 'solid',
            fgColor: { argb: 'FFD3D3D3' }
        };

        const formulaRef = `Vulnerabilities!$B$2:$B$${vulnerabilities.length + 1}`;

        // Process references: convert all complex reference objects to simple strings
        rows = rows.map(r => {
            // Create a new object to avoid mutation problems
            const processedRow = { ...r };

            // Process reference field specifically
            if (processedRow.reference) {
                if (typeof processedRow.reference === 'object') {
                    // Convert object references to strings, preferring hyperlink over text
                    if (processedRow.reference.hyperlink) {
                        processedRow.reference = processedRow.reference.hyperlink;
                    } else if (processedRow.reference.text) {
                        processedRow.reference = processedRow.reference.text;
                    } else {
                        // For any other object format, convert to string
                        try {
                            processedRow.reference = JSON.stringify(processedRow.reference);
                        } catch (e) {
                            // If stringification fails, use a default value
                            processedRow.reference = null;
                            logger.warn(`Could not process reference for row with title: ${processedRow.vul_title}`);
                        }
                    }
                }
                // If already a string or null/undefined, leave as is
            }

            return processedRow;
        });

        // Log processed rows for debugging
        logger.info(`Processed ${rows.length} rows for Excel file`);

        // Add data validation
        worksheet.addRows(rows);
        for (let i = 2; i < 100000; i++) {
            worksheet.getCell(`C${i}`).dataValidation = {
                type: 'list',
                allowBlank: true,
                formulae: [formulaRef],
                showErrorMessage: true,
                errorTitle: 'Invalid Option',
                error: 'Please select a valid vulnerability.'
            }
        }
        logger.info("Data Validation added");

        // Add vulnerabilities sheet
        addVulnerabilitiesSheet(workbook);
        logger.info("Vulnerabilities sheet added");

        // Save the XLSX file
        await workbook.xlsx.writeFile(xlsxName);

        // Convert to ODS
        let odsPath = null;
        try {
            odsPath = await convertToOds(xlsxName);
            logger.log('info', `ods - ${odsPath}`);
        } catch (err) {
            logger.warn(`ODS conversion failed: ${err}`);
        }

        return {
            downloadName: path.basename(xlsxName),
            downloadNameOds: odsPath ? path.basename(odsPath) : null,
            filePath: xlsxName,
            filePathOds: odsPath
        };
    } catch (err) {
        logger.error(`Failed to create download files: ${err}`);
        throw new Error(`Failed to create download files: ${err}`);
    }
}

function isValidVulnerability(title) {
    return vulnerabilities.some(vuln => vuln.includes(title));
}

// Add this after the existing helper functions
async function convertToOds(xlsxPath) {
    try {
        // Get directory and filename
        const dir = path.dirname(xlsxPath);
        const filename = path.basename(xlsxPath, '.xlsx');

        return new Promise((resolve, reject) => {
            // Run soffice command to convert
            exec(`soffice --headless --convert-to ods "${xlsxPath}" --outdir "${dir}"`, (error, stdout, stderr) => {
                if (error) {
                    logger.error(`483 - Conversion error: ${error.message}`);
                    reject(error);
                    return;
                }

                const odsPath = path.join(dir, `${filename}.ods`);
                if (fs.existsSync(odsPath)) {
                    logger.info(`Successfully converted to ODS: ${odsPath}`);
                    resolve(odsPath);
                } else {
                    reject(new Error('ODS file not created'));
                }
            });
        });
    } catch (err) {
        logger.error(`198 - Failed to convert to ODS: ${err.message}`);
        throw err;
    }
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

        let workbook = new ExcelJS.Workbook();
        let jsonData = [];

        try {
            await workbook.xlsx.readFile(tempFilePath);
            const sheet = workbook.getWorksheet(1);

            if (!sheet) {
                return res.status(400).send('Uploaded file contains no worksheets.');
            }

            // Get headers from the first row
            const headers = [];
            sheet.getRow(1).eachCell((cell) => {
                headers.push(cell.value);
            });

            // Convert worksheet data to JSON
            jsonData = [];
            sheet.eachRow({ includeEmpty: false }, (row, rowNumber) => {
                if (rowNumber > 1) {
                    const rowData = {};
                    row.eachCell({ includeEmpty: true }, (cell, colNumber) => {
                        if (colNumber <= headers.length) {
                            let v = cell.value;
                            // If it’s a hyperlink object, use its URL
                            if (v && typeof v === 'object' && v.hyperlink) {
                                v = v.hyperlink;
                            }
                            // If it’s a rich-text object, join its parts
                            else if (v && typeof v === 'object' && Array.isArray(v.richText)) {
                                v = v.richText.map(part => part.text).join('');
                            }
                            // Otherwise leave v as-is (string, number, Date, or null)
                            rowData[headers[colNumber - 1]] = v;
                        }
                    });
                    jsonData.push(rowData);
                }
            });
        } catch (error) {
            return res.status(400).send(`Error reading file: ${error.message}`);
        }

        if (jsonData.length === 0) {
            return res.status(400).send('Uploaded file contains no data.');
        }

        let colFromDB;
        try {
            // Change the table name from ISSUE_MASTER to vulnerabilities
            [colFromDB] = await sequelize.query('DESC vulnerabilities');
        } catch (err) {
            throw new Error(`Database error: ${err.message}`);
        }


        const colFromDBNames = colFromDB.map(col => col.Field);
        const spreadsheetCols = Object.keys(jsonData[0]);

        const invalidCols = spreadsheetCols.filter(col => !colFromDBNames.includes(col));
        // Updated required columns for vulnerabilities
        const missingRequiredCols = ['app_id', 'vul_title', 'description']
            .filter(required => !spreadsheetCols.includes(required));

        if (invalidCols.length > 0 || missingRequiredCols.length > 0) {
            let message = '';
            if (invalidCols.length > 0) {
                message += `Invalid columns found: ${invalidCols.join(', ')}. `;
            }

            if (missingRequiredCols.length > 0) {
                message += `Missing required columns: ${missingRequiredCols.join(', ')}. `;
            }

            const templateFilename = 'template_vulnerabilities.xlsx';
            const newFilePath = path.join(UPLOADS_DIR, templateFilename);

            const templateWorkbook = new ExcelJS.Workbook();
            const templateSheet = templateWorkbook.addWorksheet('Template');

            // Define columns based on DB schema for vulnerabilities
            templateSheet.columns = colFromDBNames.map(col => {
                let width;
                switch (col) {
                    case 'vul_id': width = 10; break;
                    case 'app_id': width = 10; break;
                    case 'vul_title': width = 40; break;
                    case 'affected_url': width = 50; break;
                    case 'risk_rating': width = 15; break;
                    case 'affected_parameters': width = 30; break;
                    case 'description': width = 50; break;
                    case 'impact': width = 30; break;
                    case 'recommendation': width = 30; break;
                    case 'reference': width = 30; break;
                    case 'status': width = 15; break;
                    case 'created_on': width = 15; break;
                    case 'updated_on': width = 15; break;
                    case 'deleted_on': width = 15; break;
                    default: width = 15;
                }
                return { header: col, key: col, width };
            });

            // Format header row
            const headerRow = templateSheet.getRow(1);
            headerRow.font = { bold: true };
            headerRow.fill = {
                type: 'pattern',
                pattern: 'solid',
                fgColor: { argb: 'FFD3D3D3' }
            };

            // Add sample row with vulnerabilities structure data
            const sampleRowData = {};
            colFromDBNames.forEach(col => {
                switch (col) {
                    case 'vul_id':
                        sampleRowData[col] = 'Auto-generated';
                        break;
                    case 'app_id':
                        sampleRowData[col] = 1;
                        break;
                    case 'vul_title':
                        sampleRowData[col] = 'Cross-Site Scripting (XSS)';
                        break;
                    case 'affected_url':
                        sampleRowData[col] = 'https://example.com/vulnerable-page';
                        break;
                    case 'risk_rating':
                        sampleRowData[col] = 'High';
                        break;
                    case 'affected_parameters':
                        sampleRowData[col] = 'search, id';
                        break;
                    case 'description':
                        sampleRowData[col] = 'Detailed description of the security issue';
                        break;
                    case 'impact':
                        sampleRowData[col] = 'Potential impact of the vulnerability';
                        break;
                    case 'recommendation':
                        sampleRowData[col] = 'Recommendations to fix the issue';
                        break;
                    case 'reference':
                        sampleRowData[col] = 'OWASP Top 10 - A3:2021';
                        break;
                    case 'status':
                        sampleRowData[col] = 'Open';
                        break;
                    case 'created_on':
                        sampleRowData[col] = new Date();
                        break;
                    default:
                        sampleRowData[col] = '';
                }
            });
            logger.log('info', `${vulnerabilities}`)
            templateSheet.addRow(sampleRowData);
            const formulaRef = `Vulnerabilities!$B$2:$B$${vulnerabilities.length + 1}`;
            logger.log('info', `${formulaRef}`)
            // Add data validation
            for (let i = 2; i < 100000; i++) {
                templateSheet.getCell(`C${i}`).dataValidation = {
                    type: 'list',
                    allowBlank: true,
                    formulae: [formulaRef],
                    showErrorMessage: true,
                    errorTitle: 'Invalid Option',
                    error: 'Please select a valid vulnerability.'
                }
            }
            addVulnerabilitiesSheet(templateWorkbook);

            // Save the template file
            await templateWorkbook.xlsx.writeFile(newFilePath);

            return res.status(400).send(
                `${message} Please download the template file with valid columns. 
                <a href="/file/download/${encodeURIComponent(templateFilename)}">Download Template</a>`
            );
        }

        const validRows = [];

        jsonData.forEach((row, index) => {
            const rowNum = index + 2;
            const errors = [];

            // Validation for vulnerabilities structure
            if (!row.app_id) errors.push('Missing app_id');
            if (!row.vul_title) errors.push('Missing vul_title');
            if (!row.description) errors.push('Missing description');
            if (row.vul_title && row.vul_title.length > 100)
                errors.push('vul_title exceeds 100 character limit');
            logger.log('info', `${row.vul_title} ${isValidVulnerability(row.vul_title)}`)
            if (row.vul_title && !isValidVulnerability(row.vul_title)) {
                errors.push('vul_title must exactly match one of the predefined vulnerabilities');
            }

            const processedRow = {
                ...row,
                app_id: row.app_id || 1,
                created_on: new Date(),
                status: row.status || 'Open'
            };

            if (errors.length === 0) {
                validRows.push(processedRow);
            }
        });



        if (validRows.length > 0) {
            const lenientPatterns = vulnerabilities.map(vul => {
                const escaped = vul.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
                return escaped.replace(/\s+/g, '\\s*');
            });
            const lenientRegex = new RegExp(lenientPatterns.join('|'), 'i');
            let rowsToInsert = validRows.filter(row => lenientRegex.test(row.vul_title));
            logger.log('info', `Rows to insert: ${rowsToInsert.length}`);

            if (rowsToInsert.length === 0) {
                return res.status(400).send('No valid data found to import.');
            }

            try {
                const result = await downloadFile(origName, rowsToInsert);
                await batchInsert(rowsToInsert);
                logger.log('info', `Rows inserted: ${rowsToInsert.length}`);
                res.render('preview', {
                    rows: rowsToInsert,
                    totalRows: validRows,
                    filename: req.file.originalname,
                    downloadName: result.downloadNameOds,
                });
            } catch (error) {
                logger.log('error', `443 - ${error}`)
                return res.status(500).send(`Error preparing file: ${error}`);
            }
        } else {
            return res.status(400).send('No valid data found to import.');
        }

    } catch (err) {
        logger.log('error', `451 ${err}`)
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
        // Make one final pass to ensure all reference objects are properly stringified
        // This is critical as we're seeing references with object values despite earlier processing
        const finalProcessedRows = rows.map(row => {
            // Create a fresh copy to avoid any reference issues
            const newRow = { ...row };

            // Special handling for reference field
            if (newRow.reference !== null && newRow.reference !== undefined) {
                if (typeof newRow.reference === 'object') {
                    // Log this unexpected state for debugging
                    logger.warn(`Found object reference despite preprocessing: ${JSON.stringify(newRow.reference)}`);

                    // Extract value, with fallbacks
                    if (newRow.reference.hyperlink) {
                        newRow.reference = String(newRow.reference.hyperlink);
                    } else if (newRow.reference.text) {
                        newRow.reference = String(newRow.reference.text);
                    } else {
                        // Last resort - convert to JSON string
                        try {
                            newRow.reference = JSON.stringify(newRow.reference);
                        } catch (e) {
                            // If all else fails, set to null
                            newRow.reference = null;
                            logger.error(`Failed to process reference: ${e.message}`);
                        }
                    }
                } else if (typeof newRow.reference !== 'string' && newRow.reference !== null) {
                    // Convert any non-string, non-null values to strings
                    newRow.reference = String(newRow.reference);
                }
            }

            return newRow;
        });

        const BATCH_SIZE = 100;
        const COL_COUNT = 11;
        const placeholdersPerRow = `(${Array(COL_COUNT).fill('?').join(',')})`;

        let insertedCount = 0;

        for (let i = 0; i < finalProcessedRows.length; i += BATCH_SIZE) {
            const batch = finalProcessedRows.slice(i, i + BATCH_SIZE);
            const valuesClause = batch.map(() => placeholdersPerRow).join(',');

            // For each row, ensure the reference field is a string or null before flattening
            const flatReplacements = batch.flatMap(row => {
                // Double-check reference one last time
                let reference = row.reference;
                if (reference !== null && reference !== undefined && typeof reference === 'object') {
                    // This shouldn't happen at this point, but as a final safeguard:
                    logger.error(`Found object reference at SQL generation stage: ${JSON.stringify(reference)}`);
                    reference = null;
                }

                return [
                    row.app_id,
                    row.vul_title,
                    row.affected_url || null,
                    row.risk_rating || null,
                    row.affected_parameters || null,
                    row.description,
                    row.impact || null,
                    row.recommendation || null,
                    reference, // This should now be guaranteed to be a string or null
                    row.status || 'Open',
                    row.created_on
                ];
            });

            // Add debug logging to help identify issues
            logger.info(`Processing batch ${i / BATCH_SIZE + 1} with ${batch.length} items`);

            try {
                await sequelize.query(
                    `INSERT INTO vulnerabilities (
                        app_id,
                        vul_title,
                        affected_url,
                        risk_rating,
                        affected_parameters,
                        description,
                        impact,
                        recommendation,
                        reference,
                        status,
                        created_on
                    ) VALUES ${valuesClause}`,
                    {
                        replacements: flatReplacements,
                        type: sequelize.QueryTypes.INSERT
                    }
                );

                insertedCount += batch.length;
            } catch (innerError) {
                // Log specific details about the failing batch and values
                logger.error(`Insert error in batch ${i / BATCH_SIZE + 1}: ${innerError.message}`);
                logger.error(`Problem batch data: ${JSON.stringify(batch.map(r => ({
                    app_id: r.app_id,
                    vul_title: r.vul_title,
                    reference: r.reference,
                    reference_type: typeof r.reference
                })))}`);

                // Rethrow to trigger transaction rollback
                throw innerError;
            }
        }

        await transaction.commit();
        logger.info(`Successfully inserted ${insertedCount} rows`);
        return insertedCount;

    } catch (error) {
        await transaction.rollback();
        logger.error(`Batch insert failed: ${error}`);
        throw error;
    }
}

router.get('/download/:filename', (req, res) => {
    const filename = req.params.filename;
    const sanitizedFilename = path.basename(filename);
    const filePath = path.join(UPLOADS_DIR, sanitizedFilename);

    logger.log('info', `Looking for file: ${filePath}`);

    if (!fs.existsSync(filePath)) {
        logger.log('warn', `File not found: ${filePath}`);
        return res.status(404).send('File not found');
    }

    const fileStream = fs.createReadStream(filePath);

    // Handle stream errors
    fileStream.on('error', (err) => {
        logger.log('error', `528 - ${err}`)
        if (!res.headersSent) {
            res.status(500).send('Error streaming file');
        }
    });

    req.on('close', () => {
        fileStream.destroy();
        logger.log('info', 'Download aborted by client');
    });

    res.download(filePath, sanitizedFilename, (err) => {
        if (err) {
            logger.log('error', `541 - ${err}`)
            if (!res.headersSent) {
                res.status(500).send('Error downloading file');
            }
        } else {
            logger.log('info', `Download completed: ${sanitizedFilename}`);
        }
    });
});

router.get('/preview', async (req, res) => {
    try {
        let { filename, rows, totalRows, downloadNameOds } = req.body || req.query;

        if (!filename || !rows) {
            return res.status(400).send('Missing filename or rows in request.');
        }

        // parse JSON strings into objects
        if (typeof rows === 'string') {
            rows = JSON.parse(rows);
        }
        if (totalRows && typeof totalRows === 'string') {
            totalRows = JSON.parse(totalRows);
        } else {
            totalRows = [];
        }
        res.render('preview', {
            rows,
            totalRows,
            filename,
            downloadName: downloadNameOds,
        });
    } catch (err) {
        logger.error(`578 - ${err}`);
        res.status(500).send(`Preview generation failed: ${err.message}`);
    }
});


module.exports = router;
