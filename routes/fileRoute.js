const fs = require('fs').promises;
const express = require('express');
const path = require('path');
const multer = require('multer');
const ExcelJS = require('exceljs');
const winston = require('winston');
const crypto = require('crypto');
const router = express.Router();
const { Transaction } = require('sequelize');

const {
    addVulnerabilitiesSheet,
    downloadFile,
    isValidVulnerability,
    processZIPOrRAR,
    ImageTableOps,
    addImageAddress
} = require('../utils/file.js');

// Enhanced logger configuration
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.errors({ stack: true }),
        winston.format.printf(({ timestamp, level, message, stack }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message}${stack ? '\n' + stack : ''}`;
        })
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        }),
        new winston.transports.File({ 
            filename: 'app.log',
            maxsize: 10 * 1024 * 1024, // 10MB
            maxFiles: 5
        }),
    ],
});

// Security constants
const UPLOADS_DIR = path.resolve(__dirname, '../uploads/');
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
const ALLOWED_MIME_TYPES = {
    spreadsheet: [
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.oasis.opendocument.spreadsheet'
    ],
    archive: [
        'application/zip',
        'application/x-rar-compressed',
        'application/x-zip-compressed'
    ]
};

// Secure multer configuration
const upload = multer({
    dest: UPLOADS_DIR,
    limits: { 
        fileSize: MAX_FILE_SIZE,
        files: 2,
        fieldSize: 1024 * 1024 // 1MB field size limit
    },
    fileFilter: (req, file, cb) => {
        const isSpreadsheet = ALLOWED_MIME_TYPES.spreadsheet.includes(file.mimetype);
        const isArchive = ALLOWED_MIME_TYPES.archive.includes(file.mimetype);
        
        if (file.fieldname === 'file' && isSpreadsheet) {
            cb(null, true);
        } else if (file.fieldname === 'referenceZip' && isArchive) {
            cb(null, true);
        } else {
            cb(new Error(`Invalid file type for ${file.fieldname}: ${file.mimetype}`));
        }
    }
});

const { sequelize, getVulnerabilities } = require('../db.js');

// Cache for vulnerabilities with TTL
let vulnerabilitiesCache = {
    data: [],
    lastUpdated: 0,
    ttl: 5 * 60 * 1000 // 5 minutes
};

// Load vulnerabilities with caching
async function getCachedVulnerabilities() {
    const now = Date.now();
    if (now - vulnerabilitiesCache.lastUpdated > vulnerabilitiesCache.ttl) {
        try {
            vulnerabilitiesCache.data = await getVulnerabilities();
            vulnerabilitiesCache.lastUpdated = now;
            logger.info(`Loaded ${vulnerabilitiesCache.data.length} vulnerabilities`);
        } catch (error) {
            logger.error('Failed to load vulnerabilities:', error);
            throw error;
        }
    }
    return vulnerabilitiesCache.data;
}

// Utility functions
function sanitizeFilename(filename) {
    return path.basename(filename).replace(/[^a-zA-Z0-9.-]/g, '_');
}

function generateSecureFilename(originalName) {
    const ext = path.extname(originalName);
    const hash = crypto.randomBytes(16).toString('hex');
    return `${hash}${ext}`;
}

async function validateFileExists(filePath) {
    try {
        await fs.access(filePath);
        return true;
    } catch {
        return false;
    }
}

// Enhanced error handling middleware
function handleAsyncErrors(fn) {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
}

// Main upload route
router.post('/submit', upload.fields([
    { name: 'file', maxCount: 1 },
    { name: 'referenceZip', maxCount: 1 }
]), handleAsyncErrors(async (req, res) => {
    const startTime = Date.now();
    let tempFiles = [];
    
    try {
        const reportFile = req.files['file']?.[0];
        const zipFile = req.files['referenceZip']?.[0];

        if (!reportFile || !zipFile) {
            return res.status(400).json({
                success: false,
                message: 'Both an audit report (.xlsx/.ods) and a reference zip (.zip/.rar) are required.'
            });
        }

        // Add files to cleanup list
        tempFiles.push(reportFile.path, zipFile.path);

        const reportPath = reportFile.path;
        const zipPath = zipFile.path;
        const reportName = reportFile.originalname;
        const reportExt = path.extname(reportName).toLowerCase();
        const zipExt = path.extname(zipFile.originalname).toLowerCase();

        // Validate file extensions
        if (!['.xlsx', '.ods'].includes(reportExt)) {
            return res.status(400).json({
                success: false,
                message: 'Unsupported report format. Please upload .xlsx or .ods files only.'
            });
        }

        if (!['.zip', '.rar'].includes(zipExt)) {
            return res.status(400).json({
                success: false,
                message: 'Unsupported archive format. Please upload .zip or .rar files only.'
            });
        }

        // Secure file renaming
        const secureZipPath = path.join(path.dirname(zipPath), generateSecureFilename(zipFile.originalname));
        await fs.rename(zipPath, secureZipPath);
        tempFiles.push(secureZipPath);
        
        logger.info(`Processing files: ${reportName}, ${zipFile.originalname}`);

        // Process ZIP file with error handling
        let extractedImageFiles = [];
        try {
            extractedImageFiles = await processZIPOrRAR(secureZipPath);
            logger.info(`Successfully extracted ${extractedImageFiles.length} files from archive`);
        } catch (zipError) {
            logger.error('ZIP processing error:', zipError);
            return res.status(400).json({
                success: false,
                message: `Error processing archive: ${zipError.message}`
            });
        }

        // Process spreadsheet
        const { jsonData, headers } = await processSpreadsheet(reportPath);
        
        if (jsonData.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No data found in the uploaded file.'
            });
        }

        // Validate columns and generate template if needed
        const vulnerabilities = await getCachedVulnerabilities();
        const columnValidation = await validateColumns(jsonData[0], vulnerabilities);
        
        if (!columnValidation.isValid) {
            const templateResponse = await generateTemplate(columnValidation, vulnerabilities);
            res.status(400).send(templateResponse.html);
            return;
        }

        // Process and validate data
        const { validRows, errors } = await processAndValidateData(jsonData, vulnerabilities);
        
        if (validRows.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No valid data found to import.',
                errors: errors
            });
        }

        // Add image addresses and process
        const processedRows = addImageAddress(validRows, extractedImageFiles);
        
        // Parallel processing
        const [insertResult, downloadResult] = await Promise.all([
            batchInsert(processedRows),
            downloadFile(reportName, processedRows, extractedImageFiles),
            ImageTableOps(extractedImageFiles, processedRows)
        ]);

        logger.info(`Processing completed in ${Date.now() - startTime}ms. Inserted ${insertResult} rows.`);

        const colHeaders = processedRows.length > 0 ? Object.keys(processedRows[0]) : [];
        if (!colHeaders.includes('img_ref_address')) {
            colHeaders.push('img_ref_address');
        }

        res.render('preview', {
            rows: processedRows,
            totalRows: validRows,
            filename: reportPath,
            downloadName: downloadResult.downloadNameOds,
            imageFiles: extractedImageFiles,
            vulnerabilities,
            colHeaders,
            success: true,
            message: `Successfully processed ${processedRows.length} records`
        });

    } catch (error) {
        logger.error('Upload processing error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error occurred while processing files.'
        });
    } finally {
        // Cleanup temp files
        await cleanupTempFiles(tempFiles);
    }
}));

// Process spreadsheet data
async function processSpreadsheet(filePath) {
    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.readFile(filePath);
    
    const sheet = workbook.getWorksheet(1);
    if (!sheet) {
        throw new Error('No worksheets found in the uploaded file.');
    }

    const headers = [];
    sheet.getRow(1).eachCell((cell) => {
        headers.push(cell.value);
    });

    const jsonData = [];
    sheet.eachRow({ includeEmpty: false }, (row, rowNumber) => {
        if (rowNumber > 1) {
            const rowData = {};
            row.eachCell({ includeEmpty: true }, (cell, colNumber) => {
                if (colNumber <= headers.length) {
                    let value = cell.value;
                    
                    // Handle hyperlinks and rich text
                    if (value && typeof value === 'object') {
                        if (value.hyperlink) {
                            value = value.hyperlink;
                        } else if (Array.isArray(value.richText)) {
                            value = value.richText.map(part => part.text).join('');
                        }
                    }
                    
                    rowData[headers[colNumber - 1]] = value;
                }
            });
            jsonData.push(rowData);
        }
    });

    return { jsonData, headers };
}

// Validate columns against database schema
async function validateColumns(firstRow, vulnerabilities) {
    try {
        const [dbColumns] = await sequelize.query('DESC vulnerabilities');
        const dbColumnNames = dbColumns.map(col => col.Field);
        dbColumnNames.push('img_ref_address');
        
        const spreadsheetCols = Object.keys(firstRow);
        const invalidCols = spreadsheetCols.filter(col => !dbColumnNames.includes(col));
        const requiredCols = ['app_id', 'vul_title', 'description'];
        const missingRequiredCols = requiredCols.filter(required => !spreadsheetCols.includes(required));

        if (invalidCols.length > 0 || missingRequiredCols.length > 0) {
            let message = '';
            if (invalidCols.length > 0) {
                message += `Invalid columns: ${invalidCols.join(', ')}. `;
            }
            if (missingRequiredCols.length > 0) {
                message += `Missing required columns: ${missingRequiredCols.join(', ')}.`;
            }
            
            return {
                isValid: false,
                message,
                dbColumnNames,
                invalidCols,
                missingRequiredCols
            };
        }

        return { isValid: true, dbColumnNames };
    } catch (error) {
        logger.error('Column validation error:', error);
        throw new Error(`Database schema validation failed: ${error.message}`);
    }
}

// Generate template file
async function generateTemplate(validationResult, vulnerabilities) {
    const templateFilename = `template_${Date.now()}.xlsx`;
    const templatePath = path.join(UPLOADS_DIR, templateFilename);
    
    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet('Template');
    
    // Configure columns
    const columnConfig = {
        'vul_id': { width: 10 },
        'app_id': { width: 10 },
        'vul_title': { width: 40 },
        'affected_url': { width: 50 },
        'risk_rating': { width: 15 },
        'affected_parameters': { width: 30 },
        'description': { width: 50 },
        'impact': { width: 30 },
        'recommendation': { width: 30 },
        'reference': { width: 30 },
        'status': { width: 15 },
        'created_on': { width: 15 },
        'updated_on': { width: 15 },
        'deleted_on': { width: 15 },
        'img_ref_address': { width: 50 }
    };

    sheet.columns = validationResult.dbColumnNames.map(col => ({
        header: col,
        key: col,
        width: columnConfig[col]?.width || 15
    }));

    // Style header row
    const headerRow = sheet.getRow(1);
    headerRow.font = { bold: true };
    headerRow.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFD3D3D3' }
    };

    // Add sample data
    const sampleData = {
        'vul_id': 2,
        'app_id': 1,
        'vul_title': 'Cross-Site Scripting (XSS)',
        'affected_url': 'https://example.com/vulnerable-page',
        'risk_rating': 'High',
        'affected_parameters': 'search, id',
        'description': 'Detailed description of the security issue',
        'impact': 'Potential impact of the vulnerability',
        'recommendation': 'Recommendations to fix the issue',
        'reference': 'OWASP Top 10 - A3:2021',
        'status': 'Open',
        'created_on': new Date(),
        'img_ref_address': 'screenshot1.png; screenshot2.png'
    };

    sheet.addRow(sampleData);

    // Add data validation for vulnerability titles
    const formulaRef = `Vulnerabilities!$B$2:$B$${vulnerabilities.length + 1}`;
    for (let i = 2; i < 1000; i++) {
        const vulTitleCell = sheet.getCell(`C${i}`);
        vulTitleCell.dataValidation = {
            type: 'list',
            allowBlank: true,
            formulae: [formulaRef],
            showErrorMessage: true,
            errorTitle: 'Invalid Option',
            error: 'Please select a valid vulnerability.'
        };
        
        sheet.getCell(`A${i}`).value = {
            formula: `=IF(ISBLANK(C${i}),"",INDEX(Vulnerabilities!A:A,MATCH(C${i},Vulnerabilities!B:B,0)))`
        };
    }

    addVulnerabilitiesSheet(workbook);
    await workbook.xlsx.writeFile(templatePath);

    return {
        html: `
            <html>
                <head>
                    <title>Template Download</title>
                </head>
                <body>
                    <h2>Template File Generated</h2>
                    <p>${validationResult.message}</p>
                    <a href="/file/download/${encodeURIComponent(templateFilename)}" download>
                        Download Template
                    </a>
                </body>
            </html>
        `,
        downloadURL: `/file/download/${encodeURIComponent(templateFilename)}`
    };
}

// Process and validate data rows
async function processAndValidateData(jsonData, vulnerabilities) {
    const validRows = [];
    const errors = [];
    
    const vulnerabilityTitles = vulnerabilities.map(v => v.toLowerCase());
    
    for (let i = 0; i < jsonData.length; i++) {
        const row = jsonData[i];
        const rowNum = i + 2;
        const rowErrors = [];

        // Validate required fields
        if (!row.app_id) rowErrors.push('Missing app_id');
        if (!row.vul_title) rowErrors.push('Missing vul_title');
        if (!row.description) rowErrors.push('Missing description');
        
        // Validate field lengths
        if (row.vul_title && row.vul_title.length > 100) {
            rowErrors.push('vul_title exceeds 100 character limit');
        }
        
        // Validate vulnerability title
        if (row.vul_title && !isValidVulnerability(row.vul_title)) {
            rowErrors.push('vul_title must match a predefined vulnerability');
        }

        if (rowErrors.length === 0) {
            validRows.push({
                ...row,
                app_id: parseInt(row.app_id) || 1,
                created_on: new Date(),
                status: row.status || 'Open'
            });
        } else {
            errors.push({ row: rowNum, errors: rowErrors });
        }
    }

    return { validRows, errors };
}

// Optimized batch insert with connection pooling
async function batchInsert(rows) {
    if (rows.length === 0) return 0;

    const transaction = await sequelize.transaction({
    isolationLevel: Transaction.ISOLATION_LEVELS.READ_COMMITTED
    });


    try {
        const BATCH_SIZE = 50; // Reduced batch size to prevent deadlocks
        const COL_COUNT = 11;
        let insertedCount = 0;

        // Process batches sequentially to avoid deadlocks
        for (let i = 0; i < rows.length; i += BATCH_SIZE) {
            const batch = rows.slice(i, i + BATCH_SIZE);
            const processedBatch = batch.map(row => ({
                ...row,
                reference: sanitizeReference(row.reference)
            }));

            const placeholders = processedBatch.map(() => 
                `(${Array(COL_COUNT).fill('?').join(',')})`
            ).join(',');

            const values = processedBatch.flatMap(row => [
                row.app_id,
                row.vul_title,
                row.affected_url || null,
                row.risk_rating || null,
                row.affected_parameters || null,
                row.description,
                row.impact || null,
                row.recommendation || null,
                row.reference,
                row.status || 'Open',
                row.created_on
            ]);

            await sequelize.query(
                `INSERT INTO vulnerabilities (
                    app_id, vul_title, affected_url, risk_rating, affected_parameters,
                    description, impact, recommendation, reference, status, created_on
                ) VALUES ${placeholders}`,
                {
                    replacements: values,
                    type: sequelize.QueryTypes.INSERT,
                    transaction
                }
            );

            insertedCount += batch.length;
            logger.info(`Inserted batch ${Math.floor(i / BATCH_SIZE) + 1}: ${batch.length} rows`);
        }

        await transaction.commit();
        logger.info(`Successfully inserted ${insertedCount} total rows`);
        return insertedCount;

    } catch (error) {
        await transaction.rollback();
        logger.error('Batch insert failed:', error);
        throw new Error(`Database insert failed: ${error.message}`);
    }
}

// Sanitize reference field
function sanitizeReference(reference) {
    if (reference === null || reference === undefined) return null;
    
    if (typeof reference === 'object') {
        if (reference.hyperlink) return String(reference.hyperlink);
        if (reference.text) return String(reference.text);
        try {
            return JSON.stringify(reference);
        } catch {
            return null;
        }
    }
    
    return String(reference);
}

// Secure file download
router.get('/download/:filename', handleAsyncErrors(async (req, res) => {
    const filename = sanitizeFilename(req.params.filename);
    const filePath = path.join(UPLOADS_DIR, filename);

    if (!await validateFileExists(filePath)) {
        logger.warn(`Download attempt for non-existent file: ${filename}`);
        return res.status(404).json({ success: false, message: 'File not found' });
    }

    // Security check: ensure file is within uploads directory
    if (!filePath.startsWith(UPLOADS_DIR)) {
        logger.warn(`Security violation: Path traversal attempt for ${filename}`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }

    res.download(filePath, filename, (err) => {
        if (err) {
            logger.error('Download error:', err);
            if (!res.headersSent) {
                res.status(500).json({ success: false, message: 'Download failed' });
            }
        } else {
            logger.info(`File downloaded successfully: ${filename}`);
        }
    });
}));

// Preview route with enhanced security
router.get('/preview', handleAsyncErrors(async (req, res) => {
    const { filename, rows, totalRows, downloadNameOds, colHeaders, imageFiles } = req.query;

    if (!filename || !rows) {
        return res.status(400).json({
            success: false,
            message: 'Missing required parameters'
        });
    }

    try {
        const parsedRows = typeof rows === 'string' ? JSON.parse(rows) : rows;
        const parsedTotalRows = typeof totalRows === 'string' ? JSON.parse(totalRows) : totalRows || [];
        const vulnerabilities = await getCachedVulnerabilities();

        // Add vulnerability IDs
        parsedTotalRows.forEach(row => {
            const matchIndex = vulnerabilities.findIndex(vul => vul.vul_title === row.vul_title);
            row.vul_id = matchIndex >= 0 ? matchIndex + 1 : null;
        });

        res.render('preview', {
            rows: parsedTotalRows,
            filename: sanitizeFilename(filename),
            downloadName: downloadNameOds,
            imageFiles: imageFiles || [],
            colHeaders: colHeaders || []
        });

    } catch (error) {
        logger.error('Preview generation error:', error);
        res.status(500).json({
            success: false,
            message: 'Preview generation failed'
        });
    }
}));

// Secure image preview
router.get('/image/preview/:filename', handleAsyncErrors(async (req, res) => {
    const filename = sanitizeFilename(req.params.filename);
    
    try {
        const foundFiles = await findImageFiles(UPLOADS_DIR, filename);
        
        if (foundFiles.length === 0) {
            logger.warn(`Image not found: ${filename}`);
            return res.status(404).json({ success: false, message: 'Image not found' });
        }

        // Get the most recent file
        foundFiles.sort((a, b) => b.mtime - a.mtime);
        const imagePath = foundFiles[0].path;

        // Security check
        if (!imagePath.startsWith(UPLOADS_DIR)) {
            logger.warn(`Security violation: Image path traversal attempt for ${filename}`);
            return res.status(403).json({ success: false, message: 'Access denied' });
        }

        res.sendFile(imagePath);
        
    } catch (error) {
        logger.error('Image preview error:', error);
        res.status(500).json({ success: false, message: 'Error loading image' });
    }
}));

// Helper function to find image files
async function findImageFiles(dir, targetFilename) {
    const results = [];
    
    try {
        const entries = await fs.readdir(dir, { withFileTypes: true });
        
        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            
            if (entry.isDirectory()) {
                const subResults = await findImageFiles(fullPath, targetFilename);
                results.push(...subResults);
            } else if (entry.isFile() && entry.name === targetFilename) {
                const stats = await fs.stat(fullPath);
                results.push({ path: fullPath, mtime: stats.mtime });
            }
        }
    } catch (error) {
        logger.error(`Error searching directory ${dir}:`, error);
    }
    
    return results;
}

// Cleanup temporary files
async function cleanupTempFiles(filePaths) {
    for (const filePath of filePaths) {
        try {
            if (await validateFileExists(filePath)) {
                await fs.unlink(filePath);
                logger.info(`Cleaned up temp file: ${filePath}`);
            }
        } catch (error) {
            logger.warn(`Failed to cleanup temp file ${filePath}:`, error.message);
        }
    }
}

// Error handling middleware
router.use((error, req, res, next) => {
    logger.error('Route error:', error);
    
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({
                success: false,
                message: 'File too large. Maximum size is 50MB.'
            });
        }
        if (error.code === 'LIMIT_FILE_COUNT') {
            return res.status(400).json({
                success: false,
                message: 'Too many files uploaded.'
            });
        }
    }
    
    res.status(500).json({
        success: false,
        message: 'An unexpected error occurred.'
    });
});

module.exports = router;