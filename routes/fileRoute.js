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
        
        const colHeaders = [
            'issue_master_id',
            'issue_master_key', 'issue_title', 'description', 'impact',
            'recommendation', 'owasp_ref_no', 'cwe_cve_ref_no',
            'appl_type', 'audit_methodology_type', 'created_by_id',
            'created_on', 'is_updated', 'updated_by_user',
            'deleted_on'
        ];
        
        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Valid Rows');
        
        // Define columns
        worksheet.columns = [
            { header: 'issue_master_id', key: 'issue_master_id', width: 15 },
            { header: 'issue_master_key', key: 'issue_master_key', width: 15 },
            { header: 'issue_title', key: 'issue_title', width: 40 },
            { header: 'description', key: 'description', width: 50 },
            { header: 'impact', key: 'impact', width: 30 },
            { header: 'recommendation', key: 'recommendation', width: 30 },
            { header: 'owasp_ref_no', key: 'owasp_ref_no', width: 15 },
            { header: 'cwe_cve_ref_no', key: 'cwe_cve_ref_no', width: 15 },
            { header: 'appl_type', key: 'appl_type', width: 10 },
            { header: 'audit_methodology_type', key: 'audit_methodology_type', width: 20 },
            { header: 'created_by_id', key: 'created_by_id', width: 15 },
            { header: 'created_on', key: 'created_on', width: 20 },
            { header: 'is_updated', key: 'is_updated', width: 10 },
            { header: 'updated_by_user', key: 'updated_by_user', width: 15 },
            { header: 'deleted_on', key: 'deleted_on', width: 20 }
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

        // Add data validation
        worksheet.addRows(rows);
        for(let i = 2; i<100000; i++){
            worksheet.getCell(`C${i}`).dataValidation = {
                type: 'list',
                allowBlank: true,
                formulae: [formulaRef],
                showErrorMessage: true,
                errorTitle: 'Invalid Option',
                error: 'Please select a valid vulnerability.'
            }
        }        
        logger.info({
            level: 'info',
            message : "Data Validation added"
        })
        // Add vulnerabilities sheet
        addVulnerabilitiesSheet(workbook);
        logger.info({
            level: 'info',
            message : "Vulnerabilities sheet added"
        })

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
        logger.error(`164 - Failed to create download files: ${err}`);
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
                if (rowNumber > 1) { // Skip header row
                    const rowData = {};
                    row.eachCell({ includeEmpty: true }, (cell, colNumber) => {
                        if (colNumber <= headers.length) {
                            rowData[headers[colNumber - 1]] = cell.value;
                        }
                    });
                    jsonData.push(rowData);
                }
            });
        } catch (error) {
            return res.status(400).send(`Error reading file: ${error.message}`);
        }

        if (jsonData.length ===  0) {
            return res.status(400).send('Uploaded file contains no data.');
        }

        let colFromDB;
            try {
                [colFromDB] = await sequelize.query('DESC ISSUE_MASTER');
            } catch (err) {
                throw new Error(`Database error: ${err.message}`);
            }

            
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
            
            const templateFilename = 'template_issue_master.xlsx';
            const newFilePath = path.join(UPLOADS_DIR, templateFilename);

            const templateWorkbook = new ExcelJS.Workbook();
            const templateSheet = templateWorkbook.addWorksheet('Template');
            
            // Define columns based on DB schema
            templateSheet.columns = colFromDBNames.map(col => {
                let width;
                switch(col) {
                    case 'issue_master_id': width = 15; break;
                    case 'issue_title': width = 40; break;
                    case 'description': width = 50; break;
                    case 'impact': width = 30; break;
                    case 'recommendation': width = 30; break;
                    case 'owasp_ref_no': width = 15; break;
                    case 'cwe_cve_ref_no': width = 15; break;
                    case 'appl_type': width = 10; break;
                    case 'audit_methodology_type': width = 20; break;
                    case 'created_by_id': width = 15; break;
                    case 'created_on': width = 20; break;
                    case 'is_updated': width = 10; break;
                    case 'updated_by_user': width = 15; break;
                    case 'deleted_on': width = 20; break;
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
            
            // Add sample row
            const sampleRowData = {};
            colFromDBNames.forEach(col => {
                switch(col) {
                    case 'issue_master_id':
                        sampleRowData[col] = 'Auto-generated';
                        break;
                    case 'issue_title':
                        sampleRowData[col] = 'Cross-Site Scripting (XSS)';  
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
                    case 'appl_type':
                        sampleRowData[col] = 1;
                        break;
                    case 'audit_methodology_type':
                        sampleRowData[col] = 200;
                        break;
                    case 'created_by_id':
                        sampleRowData[col] = 1;
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
            for(let i = 2; i<100000; i++){
                templateSheet.getCell(`C${i}`).dataValidation = {
                    type: 'list',
                    allowBlank: true,
                    formulae: [formulaRef],
                    showErrorMessage: true,
                    errorTitle: 'Invalid Option',
                    error: 'Please select a valid vulnerability.'
                }
            }  
            
            // Add vulnerabilities sheet
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
            
            if (!row.issue_title) errors.push('Missing issue_title');
            if (!row.description) errors.push('Missing description');
            if (row.issue_title && row.issue_title.length > 300) 
                errors.push('issue_title exceeds 300 character limit');
            logger.log('info', `${row.issue_title} ${isValidVulnerability(row.issue_title)}`)
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
            }
        });
        
       
        
        if (validRows.length > 0) {
            const lenientPatterns = vulnerabilities.map(vul => {
                const escaped = vul.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
                return escaped.replace(/\s+/g, '\\s*');
            });
            const lenientRegex = new RegExp(lenientPatterns.join('|'), 'i');
            let rowsToInsert = validRows.filter(row => lenientRegex.test(row.issue_title));
            logger.log('info',`Rows to insert: ${rowsToInsert.length}`);
            
            if (rowsToInsert.length === 0) {
                return res.status(400).send('No valid data found to import.');
            }
            
            try {
                const result = await downloadFile(origName, rowsToInsert);
                await batchInsert(rowsToInsert);
                logger.log('info',`Rows inserted: ${rowsToInsert.length}`);
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
    const BATCH_SIZE = 100;
    const COL_COUNT = 13; // number of columns in your INSERT
    const placeholdersPerRow = `(${Array(COL_COUNT).fill('?').join(',')})`;

    let insertedCount = 0;

    for (let i = 0; i < rows.length; i += BATCH_SIZE) {
      const batch = rows.slice(i, i + BATCH_SIZE);

      // “(?,?…?)” × batch.length, joined with commas
      const valuesClause = batch.map(() => placeholdersPerRow).join(',');

      // flatten each row’s 13 values in order
      const flatReplacements = batch.flatMap(row => [
        row.issue_master_key    || null,
        row.issue_title,
        row.description,
        row.impact              || null,
        row.recommendation      || null,
        row.owasp_ref_no        || null,
        row.cwe_cve_ref_no      || null,
        row.appl_type,
        row.audit_methodology_type,
        row.created_by_id,
        row.created_on,
        row.is_updated,
        row.updated_by_user
      ]);

      await sequelize.query(
        `INSERT INTO issue_master (
           issue_master_key,
           issue_title,
           description,
           impact,
           recommendation,
           owasp_ref_no,
           cwe_cve_ref_no,
           appl_type,
           audit_methodology_type,
           created_by_id,
           created_on,
           is_updated,
           updated_by_user
         ) VALUES ${valuesClause}`,
        {
          replacements: flatReplacements,
          type: sequelize.QueryTypes.INSERT
        }
      );

      insertedCount += batch.length;
    }

    await transaction.commit();
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
    
    logger.log('info',`Looking for file: ${filePath}`);

    if (!fs.existsSync(filePath)) {
        logger.log('warn',`File not found: ${filePath}`);
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
        logger.log('info','Download aborted by client');
    });

    res.download(filePath, sanitizedFilename, (err) => {
        if (err) {
            logger.log('error', `541 - ${err}`)
            if (!res.headersSent) {
                res.status(500).send('Error downloading file');
            }
        } else {
            logger.log('info',`Download completed: ${sanitizedFilename}`);
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