-- Title: Potential Dropper Script Execution Via WScript/CScript/MSHTA
-- ID: cea72823-df4d-4567-950c-0b579eaf0846
-- Status: test
-- Level: medium
-- Author: Margaritis Dimitrios (idea), Florian Roth (Nextron Systems), oscd.community, Nasreddine Bencherchali (Nextron Systems), Dave Johnson
-- Date: 2019-01-16
-- Tags: attack.execution, attack.t1059.005, attack.t1059.007
-- Description: Detects wscript/cscript/mshta executions of scripts located in user directories
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((Image ILIKE '%\\wscript.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\mshta.exe')) AND ((CommandLine ILIKE '%.hta%' OR CommandLine ILIKE '%.js%' OR CommandLine ILIKE '%.jse%' OR CommandLine ILIKE '%.vba%' OR CommandLine ILIKE '%.vbe%' OR CommandLine ILIKE '%.vbs%' OR CommandLine ILIKE '%.wsf%' OR CommandLine ILIKE '%.wsh%')) AND ((CommandLine ILIKE '%:\\Perflogs\\%' OR CommandLine ILIKE '%:\\Temp\\%' OR CommandLine ILIKE '%:\\Tmp\\%' OR CommandLine ILIKE '%:\\Users\\Public\\%' OR CommandLine ILIKE '%:\\Windows\\Temp\\%' OR CommandLine ILIKE '%\\AppData\\Local\\Temp\\%' OR CommandLine ILIKE '%\\AppData\\Roaming\\Temp\\%' OR CommandLine ILIKE '%\\Start Menu\\Programs\\Startup\\%' OR CommandLine ILIKE '%\\Temporary Internet%' OR CommandLine ILIKE '%\\Windows\\Temp%' OR CommandLine ILIKE '%%LocalAppData%\\Temp\\%' OR CommandLine ILIKE '%%TEMP%%' OR CommandLine ILIKE '%%TMP%%')))
