-- Title: Suspicious XOR Encoded PowerShell Command
-- ID: bb780e0c-16cf-4383-8383-1e5471db6cf9
-- Status: test
-- Level: medium
-- Author: Sami Ruohonen, Harish Segar, Tim Shelton, Teymur Kheirkhabarov, Vasiliy Burov, oscd.community, Nasreddine Bencherchali
-- Date: 2018-09-05
-- Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1140, attack.t1027
-- Description: Detects presence of a potentially xor encoded powershell command
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%ForEach%' OR CommandLine LIKE '%for(%' OR CommandLine LIKE '%for %' OR CommandLine LIKE '%-join %' OR CommandLine LIKE '%-join'%' OR CommandLine LIKE '%-join\"%' OR CommandLine LIKE '%-join`%' OR CommandLine LIKE '%::Join%' OR CommandLine LIKE '%[char]%')) AND (CommandLine LIKE '%bxor%') AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll')) OR (Description = 'Windows PowerShell') OR (Product = 'PowerShell Core 6')))
