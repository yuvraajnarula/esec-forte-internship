const path = require('path');
const winston = require('winston');
const { createExtractorFromFile } = require('node-unrar-js');
const fs = require('fs');
const ExcelJS = require('exceljs');
const { exec } = require('child_process');
const extract = require('extract-zip')
const { getVulnerabilities, sequelize } = require('../db');


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

async function addImageProofSheet(workbook, rows) {
    const imageSheet = workbook.addWorksheet('Image Proofs');
    imageSheet.columns = [
        { header: 'Vulnerability ID', key: 'vul_id', width: 15 },
        { header: 'Image Path', key: 'image_path', width: 60 },
        { header: 'Image Preview', key: 'image_preview', width: 40 }
    ];

    rows.forEach((row, index) => {
        const imgRefAddress = row.img_ref_address || '';
        const imagePaths = imgRefAddress.split(';').map(path => path.trim());
        let imageFound = false;

        imagePaths.forEach((imagePath) => {
            if (imagePath && fs.existsSync(imagePath)) {
                imageFound = true;
                const imageBuffer = fs.readFileSync(imagePath);
                const imageExtension = path.extname(imagePath).toLowerCase().substring(1);

                let imageType;
                switch (imageExtension) {
                    case 'jpg':
                    case 'jpeg':
                        imageType = 'jpeg';
                        break;
                    case 'png':
                        imageType = 'png';
                        break;
                    case 'gif':
                        imageType = 'gif';
                        break;
                    case 'bmp':
                        imageType = 'bmp';
                        break;
                    default:
                        imageType = null;
                }

                if (imageType) {
                    const imageId = workbook.addImage({
                        buffer: imageBuffer,
                        extension: imageType,
                    });

                    const rowIndex = index + 2; // Account for header row
                    imageSheet.addImage(imageId, {
                        tl: { col: 2, row: rowIndex - 1 },
                        ext: { width: 300, height: 200 },
                        editAs: 'oneCell',
                    });

                    imageSheet.getRow(rowIndex).height = 150; // Adjust row height for the image
                }
            }
        });

        if (!imageFound) {
            imageSheet.addRow({
                vul_id: row.vul_id,
                image_path: imgRefAddress || 'No image available',
                image_preview: '404 Not Found',
            });
        }
    });

    const headerRow = imageSheet.getRow(1);
    headerRow.font = { bold: true };
    headerRow.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFD3D3D3' }
    };

    imageSheet.properties.defaultRowHeight = 100;

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

        const colHeaders = [
            'vul_id', 'app_id', 'vul_title', 'affected_url', 'risk_rating',
            'affected_parameters', 'description', 'impact',
            'recommendation', 'reference', 'status',
            'created_on', 'updated_on', 'deleted_on', 'img_ref_address'
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
            { header: 'deleted_on', key: 'deleted_on', width: 15 },
            { header: 'img_ref_address', key: 'img_ref_address', width: 50 }
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

        logger.info(`Processed ${rows.length} rows for Excel file`);
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
        addImageProofSheet(workbook, rows);
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

function addImageAddress(rows, extractedImages) {
    try {
        logger.info(`Adding image addresses to ${rows.length} rows with ${extractedImages.length} images`);
        
        // Create a map to store used images to avoid duplicates
        const usedImages = new Set();
        
        const rowsWithImages = rows.map((row, rowIndex) => {
            const processedRow = { ...row };
            
            // Initialize img_ref_address as empty
            processedRow.img_ref_address = '';
            
            const normalizedTitle = row.vul_title
                .toLowerCase()
                .replace(/[\s_-]+/g, '') // Remove spaces and underscores
                .replace(/[^\w]/g, '');  // Remove non-alphanumeric characters

            logger.info(`Processing vulnerability: ID=${row.vul_id}, Title=${row.vul_title}, Normalized Title=${normalizedTitle}`);

            // Strategy 1: Try to match by vulnerability ID
            let matchingImages = extractedImages.filter(imagePath => {
                if (usedImages.has(imagePath)) return false;
                
                const filename = path.basename(imagePath, path.extname(imagePath))
                    .toLowerCase()
                    .replace(/[\s_-]+/g, '')
                    .replace(/[^\w]/g, '');

                return filename.includes(row.vul_id?.toString() || '');
            });

            // Strategy 2: If no match by ID, try partial title matching with keywords
            if (matchingImages.length === 0) {
                const titleKeywords = extractKeywords(row.vul_title);
                
                matchingImages = extractedImages.filter(imagePath => {
                    if (usedImages.has(imagePath)) return false;
                    
                    const filename = path.basename(imagePath, path.extname(imagePath))
                        .toLowerCase()
                        .replace(/[\s_-]+/g, '')
                        .replace(/[^\w]/g, '');

                    // Check if filename contains any of the keywords
                    return titleKeywords.some(keyword => 
                        filename.includes(keyword) || 
                        keyword.includes(filename) // For short filenames
                    );
                });
            }

            // Strategy 3: If still no match, try fuzzy matching based on common vulnerability types
            if (matchingImages.length === 0) {
                const vulnType = categorizeVulnerability(row.vul_title);
                
                matchingImages = extractedImages.filter(imagePath => {
                    if (usedImages.has(imagePath)) return false;
                    
                    const filename = path.basename(imagePath, path.extname(imagePath))
                        .toLowerCase();

                    return checkVulnerabilityTypeMatch(filename, vulnType);
                });
            }

            // Strategy 4: Sequential assignment for remaining unmatched vulnerabilities
            if (matchingImages.length === 0) {
                const availableImages = extractedImages.filter(imagePath => !usedImages.has(imagePath));
                
                if (availableImages.length > 0) {
                    // Assign the first available image
                    matchingImages = [availableImages[0]];
                    logger.info(`Sequential assignment: Assigning ${availableImages[0]} to vulnerability ID=${row.vul_id}`);
                }
            }

            // Set img_ref_address based on matching images
            if (matchingImages.length > 0) {
                // If multiple images found, concatenate them with semicolon separator
                const imageNames = matchingImages.map(imagePath => path.basename(imagePath));
                processedRow.img_ref_address = imageNames.join('; ');
                
                // Mark images as used
                matchingImages.forEach(imagePath => {
                    usedImages.add(imagePath);
                    logger.info(`Matched image: ${imagePath} for vulnerability ID=${row.vul_id}`);
                });
            } else {
                processedRow.img_ref_address = 'No image available';
                logger.warn(`No images found for vulnerability ID: ${row.vul_id}, Title: ${row.vul_title}`);
            }

            return processedRow;
        });

        logger.info(`Successfully processed image addresses for ${rowsWithImages.length} rows`);
        return rowsWithImages;
        
    } catch (error) {
        logger.error(`Error in addImageAddress: ${error.message}`);
        throw error;
    }
}

function isValidVulnerability(title) {
    return vulnerabilities.some(vuln => vuln.includes(title));
}
function isValidImage(filePath) {
    try {
        const ext = path.extname(filePath).toLowerCase();
        return IMAGE_EXTENSIONS.includes(ext) && fs.existsSync(filePath);
    } catch (err) {
        logger.error(`Invalid image file: ${filePath}, Error: ${err.message}`);
        return false;
    }
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

        try {
            const extractedFiles = await listFilesRecursive(UPLOADS_DIR);
            const imageFiles = extractedFiles.filter(file => IMAGE_EXTENSIONS.includes(path.extname(file).toLowerCase()));

            if (imageFiles.length === 0) {
                throw new Error('No image files found in archive. Please include image proofs.');
            }

            logger.info(`Found ${imageFiles.length} image(s) in the archive.`);
            return imageFiles;
        } catch (err) {
            logger.error(`Error processing ZIP/RAR file: ${err.message}`);
            throw err;
        }
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
    logger.log('info', `Listed files in directory: ${dir}`);
    logger.log('info', `Total files found: ${results.length}`);
    results.forEach(file => {
        logger.log('info', `File: ${file}`);
    });
    return results;
}
async function ImageTableOps(imageFiles, rows) {
    try {
        const imageProofs = [];        
        const usedImages = new Set();
        
        rows.forEach((row, rowIndex) => {
            const normalizedTitle = row.vul_title
                .toLowerCase()
                .replace(/[\s_-]+/g, '') // Remove spaces and underscores
                .replace(/[^\w]/g, '');  // Remove non-alphanumeric characters

            logger.info(`Processing vulnerability: ID=${row.vul_id}, Title=${row.vul_title}, Normalized Title=${normalizedTitle}`);

            // Strategy 1: Try to match by vulnerability ID
            let matchingImages = imageFiles.filter(imagePath => {
                if (usedImages.has(imagePath)) return false;
                
                const filename = path.basename(imagePath, path.extname(imagePath))
                    .toLowerCase()
                    .replace(/[\s_-]+/g, '')
                    .replace(/[^\w]/g, '');

                return filename.includes(row.vul_id.toString());
            });

            // Strategy 2: If no match by ID, try partial title matching with keywords
            if (matchingImages.length === 0) {
                const titleKeywords = extractKeywords(row.vul_title);
                
                matchingImages = imageFiles.filter(imagePath => {
                    if (usedImages.has(imagePath)) return false;
                    
                    const filename = path.basename(imagePath, path.extname(imagePath))
                        .toLowerCase()
                        .replace(/[\s_-]+/g, '')
                        .replace(/[^\w]/g, '');

                    return titleKeywords.some(keyword => 
                        filename.includes(keyword) || 
                        keyword.includes(filename) // For short filenames
                    );
                });
            }

            if (matchingImages.length === 0) {
                const vulnType = categorizeVulnerability(row.vul_title);
                
                matchingImages = imageFiles.filter(imagePath => {
                    if (usedImages.has(imagePath)) return false;
                    
                    const filename = path.basename(imagePath, path.extname(imagePath))
                        .toLowerCase();

                    return checkVulnerabilityTypeMatch(filename, vulnType);
                });
            }
           if (matchingImages.length === 0) {
                const availableImages = imageFiles.filter(imagePath => !usedImages.has(imagePath));
                
                if (availableImages.length > 0) {
                    matchingImages = [availableImages[0]];
                    logger.info(`Sequential assignment: Assigning ${availableImages[0]} to vulnerability ID=${row.vul_id}`);
                }
            }
            if (matchingImages.length > 0) {
                matchingImages.forEach(imagePath => {
                    logger.info(`Matched image: ${imagePath} for vulnerability ID=${row.vul_id}`);
                    usedImages.add(imagePath);
                    imageProofs.push([
                        row.vul_id,
                        imagePath,
                        new Date()
                    ]);
                });
            } else {
                logger.warn(`No images found for vulnerability ID: ${row.vul_id}, Title: ${row.vul_title} - Skipping database insertion`);
            }
        });

        if (imageProofs.length === 0) {
            logger.warn('No matching images found for any vulnerabilities - No database insertions will be made');
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

                logger.info(`Inserted batch ${Math.floor(i / BATCH_SIZE) + 1} of image proofs`);
            }
        } catch (error) {
            await transaction.rollback();
            logger.error(`Failed to insert image proofs: ${error.message}`);
            throw error;
        }

        await transaction.commit();
        logger.info(`Successfully linked ${imageProofs.length} images to vulnerabilities`);

    } catch (error) {
        logger.error(`Error in ImageTableOps: ${error.message}`);
        throw error;
    }
}

function extractKeywords(title) {
    const keywords = [];
    const normalizedTitle = title.toLowerCase();
    
    const vulnKeywords = [
        'xss', 'sql', 'injection', 'csrf', 'sqli', 'rce', 'lfi', 'rfi', 
        'xxe', 'ssrf', 'idor', 'bac', 'auth', 'bypass', 'upload', 'directory',
        'traversal', 'disclosure', 'leak', 'exposure', 'misconfiguration'
    ];
    
    vulnKeywords.forEach(keyword => {
        if (normalizedTitle.includes(keyword)) {
            keywords.push(keyword);
        }
    });
    
    const acronymMatch = title.match(/\(([^)]+)\)/g);
    if (acronymMatch) {
        acronymMatch.forEach(match => {
            const acronym = match.replace(/[()]/g, '').toLowerCase();
            keywords.push(acronym);
        });
    }
    
    if (keywords.length === 0) {
        const words = normalizedTitle
            .replace(/[^\w\s]/g, '')
            .split(/\s+/)
            .filter(word => word.length > 3) 
            .slice(0, 3); // Take first 3 significant words
        
        keywords.push(...words);
    }
    
    return keywords;
}
function categorizeVulnerability(title) {
    const lowerTitle = title.toLowerCase();
    
    if (lowerTitle.includes('xss') || lowerTitle.includes('cross-site scripting')) {
        return 'xss';
    } else if (lowerTitle.includes('sql') || lowerTitle.includes('injection')) {
        return 'injection';
    } else if (lowerTitle.includes('csrf') || lowerTitle.includes('cross-site request')) {
        return 'csrf';
    } else if (lowerTitle.includes('upload') || lowerTitle.includes('file')) {
        return 'upload';
    } else if (lowerTitle.includes('auth') || lowerTitle.includes('bypass')) {
        return 'auth';
    } else if (lowerTitle.includes('disclosure') || lowerTitle.includes('exposure')) {
        return 'disclosure';
    }
    
    return 'general';
}

// Helper function to match filenames against vulnerability categories
function checkVulnerabilityTypeMatch(filename, vulnType) {
    const typePatterns = {
        'xss': ['xss', 'script', 'cross', 'site'],
        'injection': ['inject', 'sql', 'sqli', 'payload'],
        'csrf': ['csrf', 'token', 'request'],
        'upload': ['upload', 'file', 'shell'],
        'auth': ['auth', 'login', 'bypass', 'access'],
        'disclosure': ['info', 'leak', 'exposure', 'error'],
        'general': ['vuln', 'exploit', 'poc', 'proof']
    };
    
    const patterns = typePatterns[vulnType] || typePatterns['general'];
    return patterns.some(pattern => filename.includes(pattern));
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
    convertToOds,
    addImageAddress,
}