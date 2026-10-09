-- Title: Potentially Suspicious Inline JavaScript Execution via NodeJS Binary
-- ID: 8537c866-072e-460d-bfff-aaf39cbd73d3
-- Status: experimental
-- Level: medium
-- Author: Microsoft (idea), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-04-21
-- Tags: attack.execution, attack.t1059.007
-- Description: Detects potentially suspicious inline JavaScript execution using Node.js with specific keywords in the command line.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%http%' AND CommandLine ILIKE '%execSync%' AND CommandLine ILIKE '%spawn%' AND CommandLine ILIKE '%fs%' AND CommandLine ILIKE '%path%' AND CommandLine ILIKE '%zlib%')) AND ((Image ILIKE '%\\node.exe') OR (OriginalFileName = 'node.exe') OR (Product = 'Node.js')))
