const path = require('path');
const winston = require('winston');
const { createExtractorFromFile } = require('node-unrar-js');
const fs = require('fs');
const ExcelJS = require('exceljs');

const { getVulnerabilities } = require('../db');


let vulnerabilities = [];
(async () => {
    try {
        vulnerabilities = await getVulnerabilities();
        logger.log('info', `Loaded vulnerabilities: ${vulnerabilities}`);
    } catch (error) {
        logger.error(`39 - Failed to load vulnerabilities: ${error.message}`);
    }
})();
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
const IMAGE_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'];

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

function addImageProofSheet(workbook, rows, extractedImages) {
    const imageSheet = workbook.addWorksheet('Image Proofs');
    imageSheet.columns = [
        { header: 'Vulnerability ID', key: 'vul_id', width: 15 },
        { header: 'Image Path', key: 'image_path', width: 60 }
    ];
    const imageProofData = [];
    rows.forEach(row => {
        const matchingImages = extractedImages.filter(imagePath => {
            const filename = path.basename(imagePath).toLowerCase();
            return filename.includes(row.vul_id) || 
                   filename.includes(row.vul_title.toLowerCase().replace(/\s+/g, '_'));
        });

        // Add an entry for each matching image
        matchingImages.forEach(imagePath => {
            imageProofData.push({
                vul_id: row.vul_id,
                image_path: imagePath
            });
        });
    });

    imageSheet.addRows(imageProofData);
    const headerRow = imageSheet.getRow(1);
    headerRow.font = { bold: true };
    headerRow.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFD3D3D3' }
    };

    return workbook;
}
async function downloadFile(filename, rows, extractedImages = []) {
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
                    if (processedRow.reference.hyperlink) {
                        processedRow.reference = processedRow.reference.hyperlink;
                    } else if (processedRow.reference.text) {
                        processedRow.reference = processedRow.reference.text;
                    } else {
                        try {
                            processedRow.reference = JSON.stringify(processedRow.reference);
                        } catch (e) {
                            processedRow.reference = null;
                            logger.warn(`Could not process reference for row with title: ${processedRow.vul_title}`);
                        }
                    }
                }
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
        addVulnerabilitiesSheet(workbook);
        logger.info("Vulnerabilities sheet added");
        
        // Add image proof sheet
        addImageProofSheet(workbook, rows, extractedImages);
        logger.info("Image proofs sheet added");

        await workbook.xlsx.writeFile(xlsxName);
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
async function processZIPOrRAR(filepath) {
    try {
        const ext = path.extname(filepath).toLowerCase();
        logger.log('info',`Processing file with extension: ${ext}`);

        if (ext === '.zip') {
            const extract = require('extract-zip');
            await extract(filepath, { dir: UPLOADS_DIR });
            logger.info(`Extracted ZIP file: ${filepath}`);
        } else if (ext === '.rar') {
            const { createExtractorFromFile } = require('node-unrar-js');
            const extractor = await createExtractorFromFile({
                filepath: filepath,
                targetPath: UPLOADS_DIR
            });
            const extracted = await extractor.extract();
            logger.info(`Extracted RAR file: ${filepath}`);
        } else {
            throw new Error(`Unsupported file type: ${ext}. Only .zip and .rar files are supported.`);
        }

        const extractedFiles = await listFilesRecursive(UPLOADS_DIR);
        const imageFiles = extractedFiles.filter(file => 
            IMAGE_EXTENSIONS.includes(path.extname(file).toLowerCase())
        );

        if (imageFiles.length === 0) {
            throw new Error('No image files found in archive. Please include image proofs.');
        }

        logger.info(`Found ${imageFiles.length} image(s) in the archive.`);
        return imageFiles;
    } catch (err) {
        logger.error(`Error processing ZIP/RAR file: ${err.message}`);
        throw err;
    }
}

async function listFilesRecursive(dir) {
    let results = [];
    const list = await fs.promises.readdir(dir, { withFileTypes: true });
    for (const file of list) {
        const filePath = path.resolve(dir, file.name);
        if (file.isDirectory()) {
            const subFiles = await listFilesRecursive(filePath);
            results = results.concat(subFiles);
        } else {
            results.push(filePath);
        }
    }
    return results;
}
async function ImageTableOps(imageFiles, rows) {
    try {
        const imageProofs = [];        
        rows.forEach(row => {
            const matchingImages = imageFiles.filter(imagePath => {
                const filename = path.basename(imagePath).toLowerCase();
                return filename.includes(row.vul_id) || 
                       filename.includes(row.vul_title.toLowerCase().replace(/\s+/g, '_'));
            });
            matchingImages.forEach(imagePath => {
                imageProofs.push([
                    row.vul_id,
                    imagePath,
                    new Date()
                ]);
            });
        });

        if (imageProofs.length === 0) {
            logger.warn('No matching images found for vulnerabilities');
            return;
        }

        const transaction = await sequelize.transaction();
        try {
            const BATCH_SIZE = 100;
            for (let i = 0; i < imageProofs.length; i += BATCH_SIZE) {
                const batch = imageProofs.slice(i, i + BATCH_SIZE);
                const placeholders = batch.map(() => '(?, ?, ?)').join(',');

                await sequelize.query(
                    `INSERT INTO image_proofs 
                    (vul_id, image_url, created_on) 
                    VALUES ${placeholders}`,
                    {
                        replacements: batch.flat(),
                        type: sequelize.QueryTypes.INSERT,
                        transaction
                    }
                );
                
                logger.info(`Inserted batch ${Math.floor(i/BATCH_SIZE) + 1} of image proofs`);
            }

            await transaction.commit();
            logger.info(`Successfully linked ${imageProofs.length} images to vulnerabilities`);

        } catch (error) {
            await transaction.rollback();
            logger.error(`Failed to insert image proofs: ${error.message}`);
            throw error;
        }

    } catch (error) {
        logger.error(`Error in ImageTableOps: ${error.message}`);
        throw error;
    }
}
async function convertToOds(xlsxPath) {
    try {
        const dir = path.dirname(xlsxPath);
        const filename = path.basename(xlsxPath, '.xlsx');

        return new Promise((resolve, reject) => {
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
module.exports = {
    addVulnerabilitiesSheet,
    addImageProofSheet,
    downloadFile,
    isValidVulnerability,
    processZIPOrRAR,
    listFilesRecursive,
    ImageTableOps,
    convertToOds
}