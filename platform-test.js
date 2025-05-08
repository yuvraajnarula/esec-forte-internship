/**
 * Platform Compatibility Test Script
 * Run this script to verify cross-platform functionality
 */
const fs = require('fs');
const path = require('path');
const xlsx = require('xlsx');
const os = require('os');
const { execSync } = require('child_process');

// Test configuration
const TEST_DIR = path.join(__dirname, 'test-data');
const EXCEL_TEST_FILE = path.join(TEST_DIR, 'test-excel.xlsx');
const ODS_TEST_FILE = path.join(TEST_DIR, 'test-libreoffice.ods');
const LOG_FILE = path.join(TEST_DIR, 'platform-test-results.log');

// Ensure test directory exists
if (!fs.existsSync(TEST_DIR)) {
    fs.mkdirSync(TEST_DIR, { recursive: true });
}

// Start logging
const log = (message) => {
    const timestamp = new Date().toISOString();
    const logMessage = `${timestamp} - ${message}\n`;
    console.log(message);
    fs.appendFileSync(LOG_FILE, logMessage);
};

log('Starting platform compatibility test');
log(`Running on: ${os.platform()} (${os.release()})`);
log(`Node.js version: ${process.version}`);

// Test Excel file creation
function createExcelTestFile() {
    try {
        log('Creating Excel test file...');
        const workbook = xlsx.utils.book_new();
        
        // Create sample data for issue_master
        const data = [
            {
                issue_master_key: 'TEST-001',
                issue_title: 'Cross-Site Scripting Vulnerability',
                description: 'Application does not properly sanitize user input before rendering it in HTML responses.',
                impact: 'Attackers could inject malicious scripts to steal user data or perform actions on behalf of victims.',
                recommendation: 'Implement input validation and output encoding to prevent XSS attacks.',
                owasp_ref_no: 'A7:2021',
                cwe_cve_ref_no: 'CWE-79',
                appl_type: 1,
                audit_methodology_type: 200
            },
            {
                issue_master_key: 'TEST-002',
                issue_title: 'SQL Injection',
                description: 'User-supplied input is concatenated directly into SQL queries.',
                impact: 'Attackers could execute arbitrary SQL commands, potentially accessing, modifying, or deleting data.',
                recommendation: 'Use parameterized queries or prepared statements to prevent SQL injection.',
                owasp_ref_no: 'A3:2021',
                cwe_cve_ref_no: 'CWE-89',
                appl_type: 1,
                audit_methodology_type: 200
            }
        ];
        
        const worksheet = xlsx.utils.json_to_sheet(data);
        xlsx.utils.book_append_sheet(workbook, worksheet, 'Issues');
        xlsx.writeFile(workbook, EXCEL_TEST_FILE);
        
        log(`Excel test file created successfully at: ${EXCEL_TEST_FILE}`);
        return true;
    } catch (error) {
        log(`Error creating Excel test file: ${error.message}`);
        return false;
    }
}

// Test LibreOffice file creation
function createOdsTestFile() {
    try {
        log('Creating LibreOffice ODS test file...');
        const workbook = xlsx.utils.book_new();
        
        // Create sample data for issue_master
        const data = [
            {
                issue_master_key: 'TEST-003',
                issue_title: 'Insecure Direct Object Reference',
                description: 'Application allows direct access to resources without proper authorization checks.',
                impact: 'Attackers could access unauthorized resources by manipulating resource identifiers.',
                recommendation: 'Implement proper authorization checks for all resource access.',
                owasp_ref_no: 'A1:2021',
                cwe_cve_ref_no: 'CWE-639',
                appl_type: 2,
                audit_methodology_type: 200
            },
            {
                issue_master_key: 'TEST-004',
                issue_title: 'Cross-Site Request Forgery',
                description: 'Application does not validate that requests originated from an authenticated user.',
                impact: 'Attackers could trick users into performing unwanted actions on a web application.',
                recommendation: 'Implement anti-CSRF tokens for all state-changing operations.',
                owasp_ref_no: 'A5:2021',
                cwe_cve_ref_no: 'CWE-352',
                appl_type: 2,
                audit_methodology_type: 200
            }
        ];
        
        const worksheet = xlsx.utils.json_to_sheet(data);
        xlsx.utils.book_append_sheet(workbook, worksheet, 'Issues');
        xlsx.writeFile(workbook, ODS_TEST_FILE);
        
        log(`LibreOffice ODS test file created successfully at: ${ODS_TEST_FILE}`);
        return true;
    } catch (error) {
        log(`Error creating LibreOffice ODS test file: ${error.message}`);
        return false;
    }
}

// Test file reading
function testFileReading() {
    try {
        log('Testing Excel file reading...');
        const excelWorkbook = xlsx.readFile(EXCEL_TEST_FILE, { cellDates: true });
        const excelSheet = excelWorkbook.Sheets[excelWorkbook.SheetNames[0]];
        const excelData = xlsx.utils.sheet_to_json(excelSheet);
        log(`Excel data read successfully. Found ${excelData.length} rows.`);
        
        log('Testing ODS file reading...');
        const odsWorkbook = xlsx.readFile(ODS_TEST_FILE, { cellDates: true });
        const odsSheet = odsWorkbook.Sheets[odsWorkbook.SheetNames[0]];
        const odsData = xlsx.utils.sheet_to_json(odsSheet);
        log(`ODS data read successfully. Found ${odsData.length} rows.`);
        
        return true;
    } catch (error) {
        log(`Error testing file reading: ${error.message}`);
        return false;
    }
}

// Test LibreOffice availability (Linux/macOS)
function testLibreOfficeAvailability() {
    if (os.platform() === 'win32') {
        log('Skipping LibreOffice availability test on Windows');
        return true;
    }
    
    try {
        log('Testing LibreOffice availability...');
        // Try to execute LibreOffice command
        const command = os.platform() === 'darwin' ? 
            'which soffice' : 'which libreoffice';
        
        const result = execSync(command, { encoding: 'utf-8' });
        log(`LibreOffice found at: ${result.trim()}`);
        return true;
    } catch (error) {
        log('LibreOffice not found. This may affect ODS file handling.');
        return false;
    }
}

// Test file paths
function testFilePaths() {
    try {
        log('Testing file path handling...');
        
        // Create a deep nested path to test path handling
        const nestedPath = path.join(TEST_DIR, 'level1', 'level2', 'level3');
        fs.mkdirSync(nestedPath, { recursive: true });
        
        const testFilePath = path.join(nestedPath, 'test-path-file.txt');
        fs.writeFileSync(testFilePath, 'Testing path handling');
        
        const content = fs.readFileSync(testFilePath, 'utf-8');
        if (content === 'Testing path handling') {
            log('File path handling test passed');
            return true;
        } else {
            log('File path handling test failed: content mismatch');
            return false;
        }
    } catch (error) {
        log(`Error testing file paths: ${error.message}`);
        return false;
    }
}

// Run all tests
async function runTests() {
    const results = {
        excelCreation: createExcelTestFile(),
        odsCreation: createOdsTestFile(),
        fileReading: testFileReading(),
        libreofficeAvailability: testLibreOfficeAvailability(),
        filePaths: testFilePaths()
    };
    
    log('\n----- TEST RESULTS -----');
    for (const [test, result] of Object.entries(results)) {
        log(`${test}: ${result ? 'PASSED' : 'FAILED'}`);
    }
    
    const allPassed = Object.values(results).every(result => result === true);
    log(`\nOVERALL RESULT: ${allPassed ? 'PASSED' : 'FAILED'}`);
    log('See detailed logs in: ' + LOG_FILE);
}

// Execute tests
runTests().catch(error => {
    log(`Unhandled error during tests: ${error.message}`);
    process.exit(1);
});