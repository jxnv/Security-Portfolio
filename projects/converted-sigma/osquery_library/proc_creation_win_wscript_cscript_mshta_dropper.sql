-- Title: Potential Dropper Script Execution Via WScript/CScript/MSHTA
-- ID: cea72823-df4d-4567-950c-0b579eaf0846
-- Status: test
-- Level: medium
-- Author: Margaritis Dimitrios (idea), Florian Roth (Nextron Systems), oscd.community, Nasreddine Bencherchali (Nextron Systems), Dave Johnson
-- Date: 2019-01-16
-- Tags: attack.execution, attack.t1059.005, attack.t1059.007
-- Description: Detects wscript/cscript/mshta executions of scripts located in user directories
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe")) AND ((CommandLine LIKE '%.hta%' OR CommandLine LIKE '%.js%' OR CommandLine LIKE '%.jse%' OR CommandLine LIKE '%.vba%' OR CommandLine LIKE '%.vbe%' OR CommandLine LIKE '%.vbs%' OR CommandLine LIKE '%.wsf%' OR CommandLine LIKE '%.wsh%')) AND ((CommandLine LIKE '%:\\Perflogs\\%' OR CommandLine LIKE '%:\\Temp\\%' OR CommandLine LIKE '%:\\Tmp\\%' OR CommandLine LIKE '%:\\Users\\Public\\%' OR CommandLine LIKE '%:\\Windows\\Temp\\%' OR CommandLine LIKE '%\\AppData\\Local\\Temp\\%' OR CommandLine LIKE '%\\AppData\\Roaming\\Temp\\%' OR CommandLine LIKE '%\\Start Menu\\Programs\\Startup\\%' OR CommandLine LIKE '%\\Temporary Internet%' OR CommandLine LIKE '%\\Windows\\Temp%' OR CommandLine LIKE '%%LocalAppData%\\Temp\\%' OR CommandLine LIKE '%%TEMP%%' OR CommandLine LIKE '%%TMP%%')))
