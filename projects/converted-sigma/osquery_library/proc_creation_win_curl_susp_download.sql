-- Title: Suspicious Curl.EXE Download
-- ID: e218595b-bbe7-4ee5-8a96-f32a24ad3468
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2020-07-03
-- Tags: attack.command-and-control, attack.t1105
-- Description: Detects a suspicious curl process start on Windows and outputs the requested document to a local file
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\curl.exe") OR (Product = 'The curl executable')) AND (((CommandLine="*.dll" OR CommandLine="*.gif" OR CommandLine="*.jpeg" OR CommandLine="*.jpg" OR CommandLine="*.png" OR CommandLine="*.temp" OR CommandLine="*.tmp" OR CommandLine="*.txt" OR CommandLine="*.vbe" OR CommandLine="*.vbs")) OR ((CommandLine LIKE '%%AppData%%' OR CommandLine LIKE '%%Public%%' OR CommandLine LIKE '%%Temp%%' OR CommandLine LIKE '%%tmp%%' OR CommandLine LIKE '%\\AppData\\%' OR CommandLine LIKE '%\\Desktop\\%' OR CommandLine LIKE '%\\Temp\\%' OR CommandLine LIKE '%\\Users\\Public\\%' OR CommandLine LIKE '%C:\\PerfLogs\\%' OR CommandLine LIKE '%C:\\ProgramData\\%' OR CommandLine LIKE '%C:\\Windows\\Temp\\%'))) AND NOT ((ParentImage = 'C:\\Program Files\\Git\\usr\\bin\\sh.exe' AND Image = 'C:\\Program Files\\Git\\mingw64\\bin\\curl.exe' AND (CommandLine LIKE '%--silent --show-error --output %' AND CommandLine LIKE '%gfw-httpget-%' AND CommandLine LIKE '%AppData%'))))
