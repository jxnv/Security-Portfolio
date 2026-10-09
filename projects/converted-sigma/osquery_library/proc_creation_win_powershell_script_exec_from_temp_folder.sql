-- Title: Potentially Suspicious Powershell Script Execution From Temp Folder
-- ID: a6a39bdb-935c-4f0a-ab77-35f4bbf44d33
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), Max Altgelt (Nextron Systems), Tim Shelton
-- Date: 2021-07-14
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects a potentially suspicious powershell script executions from temporary folder
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe") AND (CommandLine LIKE '%\\Windows\\Temp%' OR CommandLine LIKE '%\\Temporary Internet%' OR CommandLine LIKE '%\\AppData\\Local\\Temp%' OR CommandLine LIKE '%\\AppData\\Roaming\\Temp%' OR CommandLine LIKE '%%TEMP%%' OR CommandLine LIKE '%%TMP%%' OR CommandLine LIKE '%%LocalAppData%\\Temp%')) AND NOT (((CommandLine LIKE '%\\Windows\\system32\\config\\systemprofile\\AppData\\Local\\Temp\\Amazon\\EC2-Windows\\%') OR ((ParentImage = 'C:\\Windows\\System32\\Msiexec.exe' OR ParentImage = 'C:\\Windows\\SysWOW64\\Msiexec.exe') AND Image="*\\powershell.exe" AND (CommandLine LIKE '%-NoProfile -ExecutionPolicy Bypass -Command%' AND CommandLine LIKE '%AppData\\Local\\Temp\\%' AND CommandLine LIKE '%Install-Chocolatey.ps1%')) OR ((CommandLine LIKE '% >%' OR CommandLine LIKE '%Out-File%' OR CommandLine LIKE '%ConvertTo-Json%')) OR (CommandLine LIKE '%-WindowStyle hidden -Verb runAs%'))))
