-- Title: Execution of Powershell Script in Public Folder
-- ID: fb9d3ff7-7348-46ab-af8c-b55f5fbf39b4
-- Status: test
-- Level: high
-- Author: Max Altgelt (Nextron Systems)
-- Date: 2022-04-06
-- Tags: attack.execution, attack.t1059.001
-- Description: This rule detects execution of PowerShell scripts located in the "C:\Users\Public" folder
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\powershell.exe" OR Image="*\\pwsh.exe") AND (CommandLine LIKE '%-f C:\\Users\\Public%' OR CommandLine LIKE '%-f \"C:\\Users\\Public%' OR CommandLine LIKE '%-f %Public%%' OR CommandLine LIKE '%-fi C:\\Users\\Public%' OR CommandLine LIKE '%-fi \"C:\\Users\\Public%' OR CommandLine LIKE '%-fi %Public%%' OR CommandLine LIKE '%-fil C:\\Users\\Public%' OR CommandLine LIKE '%-fil \"C:\\Users\\Public%' OR CommandLine LIKE '%-fil %Public%%' OR CommandLine LIKE '%-file C:\\Users\\Public%' OR CommandLine LIKE '%-file \"C:\\Users\\Public%' OR CommandLine LIKE '%-file %Public%%'))
