-- Title: Potentially Suspicious Inline JavaScript Execution via NodeJS Binary
-- ID: 8537c866-072e-460d-bfff-aaf39cbd73d3
-- Status: experimental
-- Level: medium
-- Author: Microsoft (idea), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-04-21
-- Tags: attack.execution, attack.t1059.007
-- Description: Detects potentially suspicious inline JavaScript execution using Node.js with specific keywords in the command line.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%http%' AND CommandLine LIKE '%execSync%' AND CommandLine LIKE '%spawn%' AND CommandLine LIKE '%fs%' AND CommandLine LIKE '%path%' AND CommandLine LIKE '%zlib%')) AND ((Image="*\\node.exe") OR (OriginalFileName = 'node.exe') OR (Product = 'Node.js')))
