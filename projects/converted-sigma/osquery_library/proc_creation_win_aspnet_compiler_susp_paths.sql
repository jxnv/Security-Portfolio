-- Title: Potentially Suspicious ASP.NET Compilation Via AspNetCompiler
-- ID: 9f50fe98-fe5c-4a2d-86c7-fad7f63ed622
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-08-14
-- Tags: attack.execution, attack.stealth, attack.t1127
-- Description: Detects execution of "aspnet_compiler.exe" with potentially suspicious paths for compilation.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image LIKE '%:\\Windows\\Microsoft.NET\\Framework\\%' OR Image LIKE '%:\\Windows\\Microsoft.NET\\Framework64\\%' OR Image LIKE '%:\\Windows\\Microsoft.NET\\FrameworkArm\\%' OR Image LIKE '%:\\Windows\\Microsoft.NET\\FrameworkArm64\\%') AND Image="*\\aspnet_compiler.exe" AND (CommandLine LIKE '%\\Users\\Public\\%' OR CommandLine LIKE '%\\AppData\\Local\\Temp\\%' OR CommandLine LIKE '%\\AppData\\Local\\Roaming\\%' OR CommandLine LIKE '%:\\Temp\\%' OR CommandLine LIKE '%:\\Windows\\Temp\\%' OR CommandLine LIKE '%:\\Windows\\System32\\Tasks\\%' OR CommandLine LIKE '%:\\Windows\\Tasks\\%'))
