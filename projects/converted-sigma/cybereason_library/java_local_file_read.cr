// Title: Potential Local File Read Vulnerability In JVM Based Application
// ID: e032f5bc-4563-4096-ae3b-064bab588685
// Status: test
// Level: high
// Author: Moti Harmats
// Date: 2023-02-11
// Tags: attack.initial-access, attack.t1190
// Description: Detects potential local file read vulnerability in JVM based apps.
// If the exceptions are caused due to user input and contain path traversal payloads then it's a red flag.
// Converted by: Sigma Universal SIEM/EDR CLI

(( == "FileNotFoundException" AND  == "/../../.."))
