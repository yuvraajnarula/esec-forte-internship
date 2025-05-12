const express = require('express');
const router = express.Router();
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

router.get('/', (req, res) => {
    res.render('index',{
        vulnerabilities : vulnerabilities
    });
});
module.exports = router;