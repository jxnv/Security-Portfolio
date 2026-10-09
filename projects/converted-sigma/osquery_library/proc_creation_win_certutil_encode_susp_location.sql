-- Title: File In Suspicious Location Encoded To Base64 Via Certutil.EXE
-- ID: 82a6714f-4899-4f16-9c1e-9a333544d4c3
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-15
-- Tags: attack.stealth, attack.t1027
-- Description: Detects the execution of certutil with the "encode" flag to encode a file to base64 where the files are located in potentially suspicious locations
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%-encode%' OR CommandLine LIKE '%/encode%')) AND ((CommandLine LIKE '%\\AppData\\Roaming\\%' OR CommandLine LIKE '%\\Desktop\\%' OR CommandLine LIKE '%\\Local\\Temp\\%' OR CommandLine LIKE '%\\PerfLogs\\%' OR CommandLine LIKE '%\\Users\\Public\\%' OR CommandLine LIKE '%\\Windows\\Temp\\%' OR CommandLine LIKE '%$Recycle.Bin%')) AND ((Image="*\\certutil.exe") OR (OriginalFileName = 'CertUtil.exe')))
