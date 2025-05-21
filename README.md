# 📊 Project Overview

This is a **Web Application** designed to streamline the **import, validation, and management of security vulnerability data** into a database (specifically into an `issue_master` SQL table).  

It allows **users (like security analysts, auditors, or developers)** to bulk upload spreadsheets containing security issues, validate them automatically against a predefined schema, insert the clean data into a database, and download processed files for reference.

> **"An enterprise-grade vulnerability management data importer and validation platform."**

---

## 🎯 Core Features

1. **Upload Security Issues in Bulk**  
   - Upload spreadsheets (`.xlsx`, `.ods`) with details like *issue title, description, impact, recommendation*, etc.  
   - Automated validation to check:  
     - Correct columns  
     - Required fields present  
     - No invalid/extra columns  

2. **Data Validation and Cleaning**  
   - Compares spreadsheet columns to the database schema (`issue_master`)  
   - Ensures key fields like *issue_title* and *description* are present  
   - Verifies content alignment with known vulnerability types (like SQLi, XSS, etc.)

3. **Insert Validated Data into Database**  
   - Inserts clean rows into the `issue_master` table in **batches (100 rows at a time)**  
   - Tracks creator and timestamps for each record

4. **Preview & Download Processed Files**  
   - Generates a preview of valid rows before insertion  
   - Allows downloading processed files (valid rows only) or **template files** to fix issues in uploads

5. **Robust Error Handling & Feedback**  
   - Provides detailed error messages for invalid uploads  
   - Suggests downloading a **template** to correct column structure and re-upload

---

## 🛠️ Technology Stack

| Tech | Usage |
|------|-------|
| **Node.js + Express.js** | Web server and routing |
| **Multer** | Handles file uploads |
| **Sequelize (SQL)** | Database interaction and querying |
| **XLSX (SheetJS)** | Reads and writes Excel and ODS spreadsheets |
| **EJS (Embedded JavaScript Templates)** | Renders preview pages |
| **MySQL or MariaDB** *(inferred from Sequelize + InnoDB)* | Underlying database |

---

## 🏛️ Primary Database Table

### `issue_master` table schema

| Column Name         | Data Type                          | Constraints / Default Value               | Description            |
|---------------------|------------------------------------|-------------------------------------------|------------------------|
| issue_master_id     | INT                                | PRIMARY KEY, AUTO_INCREMENT, NOT NULL     | Unique identifier      |
| issue_master_key    | VARCHAR(30)                        | DEFAULT NULL                              | Optional key           |
| issue_title         | VARCHAR(255)                       | NOT NULL                                  | Title of the issue     |
| description         | TEXT                                | NOT NULL                                  | Description            |
| impact              | TEXT                                | NULL                                      | Impact of the issue    |
| recommendation      | TEXT                                | NULL                                      | Recommendation         |
| owasp_ref_no        | TEXT (utf8mb3_general_ci)          | NULL                                      | OWASP reference number |
| cwe_cve_ref_no      | VARCHAR(255)                       | DEFAULT NULL                              | CWE/CVE reference      |
| appl_type           | INT                                | NOT NULL, DEFAULT -1                      | Application type       |
| audit_methodology_type | INT                             | NOT NULL, DEFAULT 200                     | Audit methodology type |
| created_by_id       | INT                                | NOT NULL                                  | Creator user ID        |
| created_on          | DATETIME                           | NOT NULL                                  | Created timestamp      |
| updated_on          | DATETIME                           | DEFAULT NULL                              | Updated timestamp      |
| is_updated          | ENUM('1', '0')                     | DEFAULT '0'                               | Is updated flag        |
| updated_by_user     | ENUM('yes', 'no')                  | DEFAULT 'no'                              | Updated by user flag   |
| deleted_on          | DATETIME                           | DEFAULT NULL                              | Deleted timestamp      |

### `vulnerabilities` table schema
| Column Name          | Data Type    | Constraints / Default Value            | Description                      |
| -------------------- | ------------ | -------------------------------------- | -------------------------------- |
| vul\_id              | INT          | PRIMARY KEY, AUTO\_INCREMENT, NOT NULL | Unique vulnerability ID          |
| app\_id              | INT          | NOT NULL                               | Associated application ID        |
| vul\_title           | VARCHAR(100) | NOT NULL                               | Title of the vulnerability       |
| affected\_url        | TEXT         | DEFAULT NULL                           | URL affected by the issue        |
| risk\_rating         | VARCHAR(50)  | DEFAULT NULL                           | Risk rating                      |
| affected\_parameters | TEXT         | DEFAULT NULL                           | Affected parameters              |
| description          | TEXT         | DEFAULT NULL                           | Description of the vulnerability |
| impact               | TEXT         | DEFAULT NULL                           | Impact of the vulnerability      |
| recommendation       | TEXT         | DEFAULT NULL                           | Recommendation to fix            |
| reference            | TEXT         | DEFAULT NULL                           | Reference links or details       |
| status               | VARCHAR(50)  | DEFAULT NULL                           | Status of the vulnerability      |
| created\_on          | DATETIME     | NOT NULL                               | Creation timestamp               |
| updated\_on          | DATETIME     | DEFAULT NULL                           | Last updated timestamp           |
| deleted\_on          | DATETIME     | DEFAULT NULL                           | Deletion timestamp               |


---

# 📋 API Routes Documentation

This document provides an overview of all available routes in the application and describes their functionality clearly.

## 🗂️ Routes Summary

| Route Path            | HTTP Method | Description                                     | File            |
|-----------------------|-------------|-------------------------------------------------|-----------------|
| `/`                   | GET         | Renders the homepage (`index.ejs`)              | indexRoute.js   |
| `/file/submit`        | POST        | Uploads and validates a spreadsheet, inserts valid rows into `issue_master` table, and renders a preview of valid rows | fileRoute.js    |
| `/file/download/:filename` | GET   | Downloads a processed file or a template file by filename | fileRoute.js    |
| `/file/preview`       | GET         | Generates and renders a preview of selected rows for download | fileRoute.js    |

---

## 📄 Route Details

### `/`  *(indexRoute.js)*

- **Method**: `GET`  
- **Description**:  
  Renders the homepage view (`index.ejs`).  
- **Usage**:  
  Typically used to show the initial landing page of the application.

---

### `/file/submit` *(fileRoute.js)*

- **Method**: `POST`  
- **Description**:  
  Handles spreadsheet uploads (`.xlsx` or `.ods`). The route:  
  - Validates file type and size (max 20 MB)  
  - Validates spreadsheet columns against the `issue_master` table schema  
  - Separates valid and invalid rows  
  - Inserts valid rows into the database  
  - Renders a preview of inserted rows  

- **Request Fields**:  
  - `file`: File upload (Spreadsheet)  

- **Response**:  
  - On success: Renders `preview.ejs` with rows inserted  
  - On failure: Returns error messages and a download link for the correct template

---

### `/file/download/:filename` *(fileRoute.js)*

- **Method**: `GET`  
- **Description**:  
  Downloads a file from the server’s `/uploads` directory. This could be:
  - A processed valid rows file  
  - A template file for correcting invalid submissions  

- **Path Parameter**:  
  - `:filename`: Name of the file to download (sanitized)

- **Response**:  
  - Serves the requested file for download  
  - Returns 404 if the file does not exist  

---

### `/file/preview` *(fileRoute.js)*

- **Method**: `GET`  
- **Description**:  
  Generates a preview page displaying uploaded rows before final download.

- **Query Parameters**:  
  - `filename`: Name of the file  
  - `rows`: JSON-encoded valid rows  
  - `totalRows`: JSON-encoded all rows (optional)

- **Response**:  
  - Renders `preview.ejs` page showing the rows and providing download link

---

## ⚙️ Notes

- **File Size Limit**: 20MB  
- **Supported File Types**: `.xlsx`, `.ods`  
- **Uploads Directory**: `/uploads/`  
- **Primary Database Table**: `issue_master`  
- **Vulnerability Filtering**: Titles are matched against a predefined list of ~30 known vulnerability types
- **File in downloadable format is .ods to support linux**
---

## 📎 Related Files

- `fileRoute.js`: Handles all file-related routes (upload, download, preview)  
- `indexRoute.js`: Handles the root homepage route  
