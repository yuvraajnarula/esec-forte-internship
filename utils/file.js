require('dotenv').config();
const path = require('path');
const winston = require('winston');
const { createExtractorFromFile } = require('node-unrar-js');
const fs = require('fs').promises;
const fsSync = require('fs');
const ExcelJS = require('exceljs');
const { exec } = require('child_process');
const { promisify } = require('util');
const extract = require('extract-zip');
const { getVulnerabilities, sequelize } = require('../db');

const execAsync = promisify(exec);

// Cache for vulnerabilities
let vulnerabilitiesCache = null;
let vulnerabilitiesPromise = null;

// Initialize vulnerabilities cache
const initializeVulnerabilities = async () => {
    if (vulnerabilitiesPromise) return vulnerabilitiesPromise;

    vulnerabilitiesPromise = (async () => {
        try {
            vulnerabilitiesCache = await getVulnerabilities();
            logger.info(`Loaded ${vulnerabilitiesCache.length} vulnerabilities into cache`);
            return vulnerabilitiesCache;
        } catch (error) {
            logger.error(`Failed to load vulnerabilities: ${error.message}`);
            vulnerabilitiesCache = [];
            return [];
        }
    })();

    return vulnerabilitiesPromise;
};

// Initialize on module load
initializeVulnerabilities();

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

// Vulnerability type patterns for better matching
const VULNERABILITY_PATTERNS = {
    'xss': ['xss', 'script', 'cross', 'site', 'scripting'],
    'injection': ['inject', 'sql', 'sqli', 'payload', 'injection'],
    'csrf': ['csrf', 'token', 'request', 'forgery'],
    'upload': ['upload', 'file', 'shell', 'malicious'],
    'auth': ['auth', 'login', 'bypass', 'access', 'authentication'],
    'disclosure': ['info', 'leak', 'exposure', 'error', 'disclosure'],
    'traversal': ['traversal', 'directory', 'path', 'lfi', 'rfi'],
    'general': ['vuln', 'exploit', 'poc', 'proof', 'security']
};

const VULNERABILITY_KEYWORDS = [
    'xss', 'sql', 'injection', 'csrf', 'sqli', 'rce', 'lfi', 'rfi',
    'xxe', 'ssrf', 'idor', 'bac', 'auth', 'bypass', 'upload', 'directory',
    'traversal', 'disclosure', 'leak', 'exposure', 'misconfiguration'
];

/**
 * Create vulnerabilities reference sheet
 */
function addVulnerabilitiesSheet(workbook) {
    const vulnSheet = workbook.addWorksheet('Vulnerabilities');

    vulnSheet.columns = [
        { header: 'S.No', key: 'sno', width: 6 },
        { header: 'Vulnerability', key: 'vulnerability', width: 50 }
    ];

    const vulnData = vulnerabilitiesCache.map((vulnerability, index) => ({
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
    const password = process.env.vuln_sheet_pwd || 'default_password';
    vulnSheet.protect(password, {
        selectLockedCells: false,
        selectUnlockedCells: false,
        formatColumns: false,
        formatRows: false,
        formatCells: false,
        insertColumns: false,
        insertRows: false,
        insertHyperlinks: false,
        deleteColumns: false,
        deleteRows: false,
        sort: false,
        autofilter: false,
        pivotTables: false,
        formatPictures: false,
        formatObjects: false,
    })
    return workbook;
}

/**
 * Main download file function with optimizations
 */
async function downloadFile(filename, rows, extractedImages = []) {
    try {
        // Ensure vulnerabilities are loaded
        await initializeVulnerabilities();

        const name = path.basename(filename);
        const safeFilename = name.replace(/[^a-zA-Z0-9_.-]/g, '_');
        const timestamp = Date.now();
        const filenameBase = `${safeFilename.replace(/\.(xlsx|ods)$/, '')}_${timestamp}`;
        const xlsxName = path.join(UPLOADS_DIR, `${filenameBase}.xlsx`);

        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Valid Rows');

        // Define columns
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
            { header: 'deleted_on', key: 'deleted_on', width: 15 },
            { header: 'img_ref_address', key: 'img_ref_address', width: 50 }
        ];

        // Add the actual data rows
        const processedRows = addImageAddress(rows, extractedImages);
        worksheet.addRows(processedRows);

        // Format header row
        const headerRow = worksheet.getRow(1);
        headerRow.font = { bold: true };
        headerRow.fill = {
            type: 'pattern',
            pattern: 'solid',
            fgColor: { argb: 'FFD3D3D3' }
        };

        // Add vulnerabilities sheet
        addVulnerabilitiesSheet(workbook);
        logger.info("Vulnerabilities sheet added");

        // Set up data validation and formulas AFTER adding data
        setupDataValidationAndFormulas(worksheet, vulnerabilitiesCache.length);

        // Write file
        await workbook.xlsx.writeFile(xlsxName);

        // Convert to ODS if needed
        let odsPath = null;
        try {
            odsPath = await convertToOds(xlsxName);
            logger.info(`ODS conversion successful: ${odsPath}`);
        } catch (error) {
            logger.warn(`ODS conversion failed: ${error.message}`);
        }

        return {
            downloadName: path.basename(xlsxName),
            downloadNameOds: odsPath ? path.basename(odsPath) : null,
            filePath: xlsxName,
            filePathOds: odsPath
        };

    } catch (error) {
        logger.error(`Failed to create download files: ${error.message}`);
        throw new Error(`Failed to create download files: ${error.message}`);
    }
}

/**
 * Validate vulnerability ID
 */
function validateVulnerabilityId(vulnId) {
    // Handle null/undefined
    if (vulnId === null || vulnId === undefined) {
        return null;
    }

    // Handle formula objects
    if (typeof vulnId === 'object') {
        if (vulnId.formula && vulnId.result !== undefined) {
            return validateVulnerabilityId(vulnId.result);
        }
        return null;
    }

    // Convert to string and validate
    const idString = String(vulnId).trim();

    // Check if it's a valid integer
    const idNumber = parseInt(idString, 10);
    if (isNaN(idNumber) || idString !== String(idNumber)) {
        return null;
    }

    return idNumber;
}

/**
 * Setup data validation and formulas
 */
function setupDataValidationAndFormulas(worksheet, vulnerabilityCount) {
    const formulaRefVulnTitle = `Vulnerabilities!$B$2:$B${vulnerabilityCount + 1}`;

    // Add data validation and formulas for a reasonable number of rows
    const MAX_ROWS = 1000;

    for (let i = 2; i <= MAX_ROWS; i++) {
        // Data validation for vulnerability title column (C)
        worksheet.getCell(`C${i}`).dataValidation = {
            type: 'list',
            allowBlank: true,
            formulae: [formulaRefVulnTitle],
            showErrorMessage: true,
            errorTitle: 'Invalid Option',
            errorStyle: 'warning',
            error: 'Please select a valid vulnerability title.'
        };

        // Set formula for vulnerability ID lookup
        try {
            const formulaString = `IF(ISBLANK(C${i}),"",INDEX(Vulnerabilities!A:A,MATCH(C${i},Vulnerabilities!B:B,0)))`;
            worksheet.getCell(`A${i}`).value = { formula: formulaString };
        } catch (error) {
            logger.warn(`Failed to set formula for cell A${i}: ${error.message}`);
            worksheet.getCell(`A${i}`).value = '';
        }
    }

    logger.info(`Data validation and formulas added for ${MAX_ROWS} rows`);
}

/**
 * Extract cell value from Excel cell
 */
function extractCellValue(cell) {
    if (!cell || cell.value === null || cell.value === undefined) {
        return null;
    }

    // Handle formula objects
    if (typeof cell.value === 'object' && cell.value.formula) {
        // If it's a formula object, use the result if available, otherwise return null
        return cell.value.result !== undefined ? cell.value.result : null;
    }

    // Handle regular values
    return cell.value;
}

/**
 * Process Excel data for database insertion
 */
function processExcelDataForDatabase(worksheet) {
    const processedRows = [];

    // Skip header row (row 1)
    for (let rowNumber = 2; rowNumber <= worksheet.rowCount; rowNumber++) {
        const row = worksheet.getRow(rowNumber);

        // Skip empty rows
        if (row.hasValues) {
            const processedRow = {
                vul_id: extractCellValue(row.getCell(1)),      // Column A
                app_id: extractCellValue(row.getCell(2)),      // Column B
                vul_title: extractCellValue(row.getCell(3)),   // Column C
                affected_url: extractCellValue(row.getCell(4)), // Column D
                risk_rating: extractCellValue(row.getCell(5)),  // Column E
                affected_parameters: extractCellValue(row.getCell(6)), // Column F
                description: extractCellValue(row.getCell(7)),  // Column G
                impact: extractCellValue(row.getCell(8)),       // Column H
                recommendation: extractCellValue(row.getCell(9)), // Column I
                reference: extractCellValue(row.getCell(10)),   // Column J
                status: extractCellValue(row.getCell(11)),      // Column K
                created_on: extractCellValue(row.getCell(12)),  // Column L
                updated_on: extractCellValue(row.getCell(13)),  // Column M
                deleted_on: extractCellValue(row.getCell(14)),  // Column N
                img_ref_address: extractCellValue(row.getCell(15)) // Column O
            };

            // Only include rows with valid data
            if (processedRow.vul_title || processedRow.affected_url) {
                processedRows.push(processedRow);
            }
        }
    }

    return processedRows;
}

/**
 * Optimized image address matching
 */
function addImageAddress(rows, extractedImages) {
    try {
        logger.info(`Processing ${rows.length} rows with ${extractedImages.length} images`);

        const usedImages = new Set();
        const imageIndex = createImageIndex(extractedImages);

        return rows.map((row, index) => {
            const processedRow = { ...row };

            // Debug log for vulnerability ID
            const vulnId = row.vul_id;
            const vulnIdType = typeof vulnId;
            const vulnIdString = vulnId !== null && vulnId !== undefined ? String(vulnId) : 'null';

            logger.debug(`Row ${index}: vul_id=${vulnIdString} (type: ${vulnIdType}), title=${row.vul_title}`);

            const matchingImages = findMatchingImages(row, imageIndex, usedImages);

            if (matchingImages.length > 0) {
                const imageNames = matchingImages.map(imagePath => path.basename(imagePath));
                processedRow.img_ref_address = imageNames.join('; ');

                matchingImages.forEach(imagePath => {
                    usedImages.add(imagePath);
                    logger.debug(`Matched: ${path.basename(imagePath)} -> ${vulnIdString}`);
                });
            } else {
                processedRow.img_ref_address = 'No image available';
                logger.warn(`No images found for vulnerability ID: ${vulnIdString}, Title: ${row.vul_title || 'undefined'}`);
            }

            return processedRow;
        });

    } catch (error) {
        logger.error(`Error in addImageAddress: ${error.message}`);
        throw error;
    }
}

/**
 * Create an index of images for faster matching
 */
function createImageIndex(extractedImages) {
    return extractedImages.map(imagePath => {
        const filename = path.basename(imagePath, path.extname(imagePath));
        const normalizedFilename = filename.toLowerCase()
            .replace(/[\s_-]+/g, '')
            .replace(/[^\w]/g, '');

        return {
            path: imagePath,
            filename,
            normalized: normalizedFilename,
            keywords: extractKeywordsFromFilename(filename)
        };
    });
}

/**
 * Find matching images using multiple strategies
 */
function findMatchingImages(row, imageIndex, usedImages) {
    const strategies = [
        () => matchByVulnerabilityId(row, imageIndex, usedImages),
        () => matchByKeywords(row, imageIndex, usedImages),
        () => matchByVulnerabilityType(row, imageIndex, usedImages),
        () => sequentialAssignment(imageIndex, usedImages)
    ];

    for (const strategy of strategies) {
        const matches = strategy();
        if (matches.length > 0) {
            return matches;
        }
    }

    return [];
}

/**
 * Match by vulnerability ID
 */
function matchByVulnerabilityId(row, imageIndex, usedImages) {
    // Safely extract vulnerability ID
    let vulnId = null;

    if (row.vul_id !== undefined && row.vul_id !== null) {
        vulnId = typeof row.vul_id === 'object' ?
            (row.vul_id.toString !== Object.prototype.toString ? row.vul_id.toString() : JSON.stringify(row.vul_id)) :
            String(row.vul_id);
    }

    if (!vulnId || vulnId === 'null' || vulnId === 'undefined') {
        logger.warn(`Invalid vulnerability ID for row: ${JSON.stringify(row)}`);
        return [];
    }

    return imageIndex
        .filter(img => !usedImages.has(img.path) && img.normalized.includes(vulnId))
        .map(img => img.path);
}

/**
 * Match by extracted keywords
 */
function matchByKeywords(row, imageIndex, usedImages) {
    const titleKeywords = extractKeywords(row.vul_title);

    return imageIndex
        .filter(img => {
            if (usedImages.has(img.path)) return false;
            return titleKeywords.some(keyword =>
                img.keywords.includes(keyword) || keyword.includes(img.normalized)
            );
        })
        .map(img => img.path);
}

/**
 * Match by vulnerability type patterns
 */
function matchByVulnerabilityType(row, imageIndex, usedImages) {
    const vulnType = categorizeVulnerability(row.vul_title);
    const patterns = VULNERABILITY_PATTERNS[vulnType] || VULNERABILITY_PATTERNS.general;

    return imageIndex
        .filter(img => {
            if (usedImages.has(img.path)) return false;
            return patterns.some(pattern => img.normalized.includes(pattern));
        })
        .map(img => img.path);
}

/**
 * Sequential assignment for remaining images
 */
function sequentialAssignment(imageIndex, usedImages) {
    const available = imageIndex.filter(img => !usedImages.has(img.path));
    return available.length > 0 ? [available[0].path] : [];
}

/**
 * Extract keywords from vulnerability title
 */
function extractKeywords(title) {
    if (!title) return [];

    const keywords = new Set();
    const normalizedTitle = title.toLowerCase();

    // Add vulnerability-specific keywords
    VULNERABILITY_KEYWORDS.forEach(keyword => {
        if (normalizedTitle.includes(keyword)) {
            keywords.add(keyword);
        }
    });

    // Extract acronyms
    const acronyms = title.match(/\(([^)]+)\)/g);
    if (acronyms) {
        acronyms.forEach(match => {
            const acronym = match.replace(/[()]/g, '').toLowerCase();
            keywords.add(acronym);
        });
    }

    // Add significant words if no specific keywords found
    if (keywords.size === 0) {
        const words = normalizedTitle
            .replace(/[^\w\s]/g, '')
            .split(/\s+/)
            .filter(word => word.length > 3)
            .slice(0, 3);

        words.forEach(word => keywords.add(word));
    }

    return Array.from(keywords);
}

/**
 * Extract keywords from filename
 */
function extractKeywordsFromFilename(filename) {
    return filename.toLowerCase()
        .replace(/[^\w\s]/g, ' ')
        .split(/\s+/)
        .filter(word => word.length > 2);
}

/**
 * Categorize vulnerability type
 */
function categorizeVulnerability(title) {
    if (!title) return 'general';

    const lowerTitle = title.toLowerCase();

    const categories = {
        'xss': ['xss', 'cross-site scripting', 'script'],
        'injection': ['sql', 'injection', 'sqli'],
        'csrf': ['csrf', 'cross-site request'],
        'upload': ['upload', 'file'],
        'auth': ['auth', 'bypass', 'authentication'],
        'disclosure': ['disclosure', 'exposure', 'leak'],
        'traversal': ['traversal', 'directory', 'lfi', 'rfi']
    };

    for (const [category, patterns] of Object.entries(categories)) {
        if (patterns.some(pattern => lowerTitle.includes(pattern))) {
            return category;
        }
    }

    return 'general';
}

/**
 * Validate vulnerability title
 */
function isValidVulnerability(title) {
    return vulnerabilitiesCache?.some(vuln => vuln.includes(title)) || false;
}

/**
 * Validate image file
 */
async function isValidImage(filePath) {
    try {
        const ext = path.extname(filePath).toLowerCase();
        if (!IMAGE_EXTENSIONS.includes(ext)) return false;

        await fs.access(filePath);
        return true;
    } catch (error) {
        logger.error(`Invalid image file ${filePath}: ${error.message}`);
        return false;
    }
}

/**
 * Process ZIP or RAR archives with better error handling
 */
async function processZIPOrRAR(filepath) {
    try {
        const ext = path.extname(filepath).toLowerCase();
        logger.info(`Processing archive: ${filepath} (${ext})`);

        if (ext === '.zip') {
            await extract(filepath, { dir: UPLOADS_DIR });
        } else if (ext === '.rar') {
            const extractor = await createExtractorFromFile({
                filepath: filepath,
                targetPath: UPLOADS_DIR
            });
            await extractor.extract();
        } else {
            throw new Error(`Unsupported archive type: ${ext}`);
        }

        const extractedFiles = await listFilesRecursive(UPLOADS_DIR);
        const imageFiles = [];

        // Validate each image file
        for (const file of extractedFiles) {
            if (await isValidImage(file)) {
                imageFiles.push(file);
            }
        }

        if (imageFiles.length === 0) {
            throw new Error('No valid image files found in archive');
        }

        logger.info(`Successfully extracted ${imageFiles.length} image files`);
        return imageFiles;

    } catch (error) {
        logger.error(`Archive processing failed: ${error.message}`);
        throw error;
    }
}

/**
 * Recursively list files with async/await
 */
async function listFilesRecursive(dir) {
    let results = [];

    try {
        const entries = await fs.readdir(dir, { withFileTypes: true });

        for (const entry of entries) {
            const filePath = path.resolve(dir, entry.name);

            if (entry.isDirectory()) {
                const subFiles = await listFilesRecursive(filePath);
                results = results.concat(subFiles);
            } else {
                results.push(filePath);
            }
        }
    } catch (error) {
        logger.error(`Error reading directory ${dir}: ${error.message}`);
    }

    return results;
}

/**
 * Optimized database operations for image proofs
 */
async function ImageTableOps(imageFiles, rows) {
    try {
        // Validate input data
        if (!Array.isArray(rows) || rows.length === 0) {
            logger.warn('No rows provided to ImageTableOps');
            return;
        }

        if (!Array.isArray(imageFiles) || imageFiles.length === 0) {
            logger.warn('No image files provided to ImageTableOps');
            return;
        }

        const imageIndex = createImageIndex(imageFiles);
        const usedImages = new Set();
        const imageProofs = [];

        // Process in batches to avoid memory issues
        const BATCH_SIZE = 50;
        for (let i = 0; i < rows.length; i += BATCH_SIZE) {
            const batch = rows.slice(i, i + BATCH_SIZE);

            batch.forEach((row, batchIndex) => {
                // Use the validation function
                const vulnId = validateVulnerabilityId(row.vul_id);

                if (vulnId === null) {
                    logger.warn(`Skipping row ${i + batchIndex} due to invalid vulnerability ID: ${JSON.stringify(row.vul_id)}`);
                    return;
                }

                const matchingImages = findMatchingImages(row, imageIndex, usedImages);

                matchingImages.forEach(imagePath => {
                    usedImages.add(imagePath);
                    // Use the validated vulnId (integer) instead of the raw value
                    imageProofs.push([vulnId, imagePath, new Date()]);
                    logger.debug(`Added image proof: ${vulnId} -> ${path.basename(imagePath)}`);
                });

                if (matchingImages.length === 0) {
                    logger.warn(`No images found for vulnerability ID: ${vulnId}, Title: ${row.vul_title || 'undefined'}`);
                }
            });
        }

        if (imageProofs.length === 0) {
            logger.warn('No matching images found - skipping database operations');
            return;
        }

        // Batch insert with transaction
        const transaction = await sequelize.transaction();
        try {
            const DB_BATCH_SIZE = 100;

            for (let i = 0; i < imageProofs.length; i += DB_BATCH_SIZE) {
                const batch = imageProofs.slice(i, i + DB_BATCH_SIZE);
                const placeholders = batch.map(() => '(?, ?, ?)').join(',');

                await sequelize.query(
                    `INSERT INTO image_proofs (vul_id, image_url, created_on) VALUES ${placeholders}`,
                    {
                        replacements: batch.flat(),
                        type: sequelize.QueryTypes.INSERT,
                        transaction
                    }
                );
            }

            await transaction.commit();
            logger.info(`Successfully inserted ${imageProofs.length} image proof records`);

        } catch (error) {
            await transaction.rollback();
            logger.error(`Database transaction failed: ${error.message}`);
            throw error;
        }

    } catch (error) {
        logger.error(`ImageTableOps failed: ${error.message}`);
        throw error;
    }
}

/**
 * Convert Excel to ODS format
 */
async function convertToOds(xlsxPath) {
    try {
        const dir = path.dirname(xlsxPath);
        const filename = path.basename(xlsxPath, '.xlsx');
        const odsPath = path.join(dir, `${filename}.ods`);

        await execAsync(`soffice --headless --convert-to ods "${xlsxPath}" --outdir "${dir}"`);

        // Verify file was created
        await fs.access(odsPath);
        logger.info(`Successfully converted to ODS: ${odsPath}`);

        return odsPath;

    } catch (error) {
        logger.error(`ODS conversion failed: ${error.message}`);
        throw new Error(`Failed to convert to ODS: ${error.message}`);
    }
}

module.exports = {
    addVulnerabilitiesSheet,
    downloadFile,
    isValidVulnerability,
    processZIPOrRAR,
    listFilesRecursive,
    ImageTableOps,
    convertToOds,
    addImageAddress,
    initializeVulnerabilities,
    processExcelDataForDatabase,
    validateVulnerabilityId
};