// Title: Insecure Proxy/DOH Transfer Via Curl.EXE
// ID: 2c1486f5-02e8-4f86-9099-b97f2da4ed77
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-07-27
// Tags: attack.execution
// Description: Detects execution of "curl.exe" with the "insecure" flag over proxy or DOH.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*--doh-insecure*" OR CommandLine: "*--proxy-insecure*")) AND ((Image="*\\curl.exe") OR (OriginalFileName: "curl.exe")))
