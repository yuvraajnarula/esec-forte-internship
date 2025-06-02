const fs = require('fs');
const express = require('express');
const path = require('path');
const multer = require('multer');
const ExcelJS = require('exceljs');
const router = express.Router();
const winston = require('winston');
const { exec } = require('child_process');
const extract = require('extract-zip')
const {
    addVulnerabilitiesSheet,
    addImageProofSheet,
    downloadFile,
    isValidVulnerability,
    processZIPOrRAR,
    listFilesRecursive,
    ImageTableOps,
    convertToOds,
    addImageAddress
} = require('../utils/file.js');

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

router.post('/submit', upload.fields([
    { name: 'file', maxCount: 1 },
    { name: 'referenceZip', maxCount: 1 }
]), async (req, res) => {
    let reportPath = null;
    let zipPath = null;
    let extractedImageFiles = [];

    try {
        const reportFile = req.files['file']?.[0];
        const zipFile = req.files['referenceZip']?.[0];

        if (!reportFile || !zipFile) {
            return res
                .status(400)
                .send('Both an audit report (.xlsx/.ods) and a reference zip (.zip/.rar) are required.');
        }

        reportPath = reportFile.path;
        zipPath = zipFile.path;
        const reportName = reportFile.originalname;
        const reportExt = path.extname(reportName).toLowerCase();
        const zipName = zipFile.originalname;
        const zipExt = path.extname(zipName).toLowerCase();
        const newZipPath = `${zipPath}${zipExt}`;
        await fs.promises.rename(zipPath, newZipPath);
        logger.info(`Renamed upload to: ${newZipPath}`);
        if (!['.xlsx', '.ods'].includes(reportExt)) {
            return res
                .status(400)
                .send('Unsupported report format—please upload .xlsx or .ods');
        }
        logger.log('info', `${zipName}, ${zipExt}`);
        if (!['.zip', '.rar'].includes(zipExt)) {
            return res
                .status(400)
                .send('Unsupported reference archive—please upload .zip or .rar');
        }
        try {
            extractedImageFiles = await processZIPOrRAR(newZipPath);
            logger.log('info', `Successfully extracted ${extractedImageFiles.length} image files from ZIP`);
        } catch (zipError) {
            logger.error(`ZIP processing error for file: ${zipFile.originalname}, ext: ${zipExt}`);
            logger.log('error', `ZIP processing error: ${zipError.message}`);
            return res.status(400).send(`Error processing ZIP file: ${zipError.message}`);
        }

        let workbook = new ExcelJS.Workbook();
        let jsonData = [];

        try {
            await workbook.xlsx.readFile(reportPath);
            const sheet = workbook.getWorksheet(1);

            if (!sheet) {
                return res.status(400).send('Uploaded file contains no worksheets.');
            }
            const headers = [];
            sheet.getRow(1).eachCell((cell) => {
                headers.push(cell.value);
            });

            jsonData = [];
            sheet.eachRow({ includeEmpty: false }, (row, rowNumber) => {
                if (rowNumber > 1) {
                    const rowData = {};
                    row.eachCell({ includeEmpty: true }, (cell, colNumber) => {
                        if (colNumber <= headers.length) {
                            let v = cell.value;
                            if (v && typeof v === 'object' && v.hyperlink) {
                                v = v.hyperlink;
                            }
                            else if (v && typeof v === 'object' && Array.isArray(v.richText)) {
                                v = v.richText.map(part => part.text).join('');
                            }
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
            [colFromDB] = await sequelize.query('DESC vulnerabilities');
        } catch (err) {
            throw new Error(`Database error: ${err.message}`);
        }
        const colFromDBNames = colFromDB.map(col => col.Field);
        colFromDBNames.push('img_ref_address'); 
        const spreadsheetCols = Object.keys(jsonData[0]);

        const invalidCols = spreadsheetCols.filter(col => !colFromDBNames.includes(col));
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
                    case 'img_ref_address': width = 50; break; // Add this case
                    default: width = 15;
                }
                return { header: col, key: col, width };
            });

            const headerRow = templateSheet.getRow(1);
            headerRow.font = { bold: true };
            headerRow.fill = {
                type: 'pattern',
                pattern: 'solid',
                fgColor: { argb: 'FFD3D3D3' }
            };

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
                    case 'img_ref_address':
                        sampleRowData[col] = 'screenshot1.png; screenshot2.png';
                        break;
                    default:
                        sampleRowData[col] = '';
                }
            });

            headerRow.font = { bold: true };
            headerRow.fill = {
                type: 'pattern',
                pattern: 'solid',
                fgColor: { argb: 'FFD3D3D3' }
            };
            logger.log('info', `${vulnerabilities}`)
            templateSheet.addRow(sampleRowData);
            const formulaRef = `Vulnerabilities!$B$2:$B$${vulnerabilities.length + 1}`;
            logger.log('info', `${formulaRef}`)
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
            addImageProofSheet(templateWorkbook, [], extractedImageFiles);
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
            logger.log('info', `Processing row ${rowNum}: ${JSON.stringify(row)}`);
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
                rowsToInsert = addImageAddress(rowsToInsert, extractedImageFiles);
                logger.info('Image addresses added to rows');

                const result = await downloadFile(reportName, rowsToInsert, extractedImageFiles);
                await batchInsert(rowsToInsert);
                await ImageTableOps(extractedImageFiles, rowsToInsert);
                logger.log('info', `Rows inserted: ${rowsToInsert.length}`);

                const colHeaders = rowsToInsert.length > 0 ? Object.keys(rowsToInsert[0]) : [];

                if (!colHeaders.includes('img_ref_address')) {
                    colHeaders.push('img_ref_address');
                }
                res.render('preview', {
                    rows: rowsToInsert,
                    totalRows: validRows,
                    filename: reportPath,
                    downloadName: result.downloadNameOds,
                    imageFiles: extractedImageFiles,
                    colHeaders
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
    // } finally {
    //     const toDelete = [];

    //     if (reportPath) toDelete.push(reportPath);
    //     if (typeof renamedZip === 'string') {
    //         toDelete.push(renamedZip);
    //     } else if (zipPath) {
    //         toDelete.push(zipPath);
    //     }

    //     extractedImageFiles.forEach(file => toDelete.push(file));

    //     toDelete.forEach(p => {
    //         fs.unlink(p, err => {
    //             if (err && err.code !== 'ENOENT') {
    //                 console.error('Failed to delete temp file', p, err);
    //             }
    //         });
    //     });
    // }
    }
});

async function batchInsert(rows) {
    const transaction = await sequelize.transaction();
    try {
        const finalProcessedRows = rows.map(row => {
            const newRow = { ...row };

            if (newRow.reference !== null && newRow.reference !== undefined) {
                if (typeof newRow.reference === 'object') {
                    logger.warn(`Found object reference despite preprocessing: ${JSON.stringify(newRow.reference)}`);
                    if (newRow.reference.hyperlink) {
                        newRow.reference = String(newRow.reference.hyperlink);
                    } else if (newRow.reference.text) {
                        newRow.reference = String(newRow.reference.text);
                    } else {
                        try {
                            newRow.reference = JSON.stringify(newRow.reference);
                        } catch (e) {
                            newRow.reference = null;
                            logger.error(`Failed to process reference: ${e.message}`);
                        }
                    }
                } else if (typeof newRow.reference !== 'string' && newRow.reference !== null) {
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

            const flatReplacements = batch.flatMap(row => {
                let reference = row.reference;
                if (reference !== null && reference !== undefined && typeof reference === 'object') {
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
                    reference,
                    row.status || 'Open',
                    row.created_on
                ];
            });

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
                logger.error(`Insert error in batch ${i / BATCH_SIZE + 1}: ${innerError.message}`);
                logger.error(`Problem batch data: ${JSON.stringify(batch.map(r => ({
                    app_id: r.app_id,
                    vul_title: r.vul_title,
                    reference: r.reference,
                    reference_type: typeof r.reference
                })))}`);

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
        let { filename, rows, totalRows, downloadNameOds, colHeaders, imageFiles } = req.body || req.query;

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
            colHeaders: colHeaders,
            imageFiles: imageFiles || []
        });
    } catch (err) {
        logger.error(`578 - ${err}`);
        res.status(500).send(`Preview generation failed: ${err.message}`);
    }
});
router.get('/image/preview/:filename', async (req, res) => {
    const filename = req.params.filename;
    const sanitizedFilename = path.basename(filename);

    async function findFiles(dir, target) {
        let results = [];
        const filesAndDirs = await fs.promises.readdir(dir, { withFileTypes: true });
        for (const entry of filesAndDirs) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                const subResults = await findFiles(fullPath, target);
                results = results.concat(subResults);
            } else if (entry.isFile() && entry.name === target) {
                const stats = await fs.promises.stat(fullPath);
                results.push({ path: fullPath, mtime: stats.mtime });
            }
        }
        return results;
    }

    try {
        const foundFiles = await findFiles(UPLOADS_DIR, sanitizedFilename);
        if (!foundFiles.length) {
            logger.log('warn', `Image file not found: ${sanitizedFilename} in uploads folder`);
            return res.status(404).send('Image file not found');
        }
        foundFiles.sort((a, b) => b.mtime - a.mtime);
        const recentFile = foundFiles[0].path;
        logger.log('info', `Found image file: ${recentFile}`);
        return res.sendFile(recentFile);
    } catch (error) {
        logger.error(`Error searching image file: ${error.message}`);
        return res.status(500).send('Error processing request');
    }
});

module.exports = router;