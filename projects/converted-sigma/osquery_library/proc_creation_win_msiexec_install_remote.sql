-- Title: Suspicious Msiexec Quiet Install From Remote Location
-- ID: 8150732a-0c9d-4a99-82b9-9efb9b90c40c
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-10-28
-- Tags: attack.stealth, attack.t1218.007
-- Description: Detects usage of Msiexec.exe to install packages hosted remotely quietly
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%-i%' OR CommandLine LIKE '%/i%' OR CommandLine LIKE '%-package%' OR CommandLine LIKE '%/package%' OR CommandLine LIKE '%-a%' OR CommandLine LIKE '%/a%' OR CommandLine LIKE '%-j%' OR CommandLine LIKE '%/j%')) AND ((Image="*\\msiexec.exe") OR (OriginalFileName = 'msiexec.exe')) AND ((CommandLine LIKE '%-q%' OR CommandLine LIKE '%/q%')) AND ((CommandLine LIKE '%http%' OR CommandLine LIKE '%\\\\\\\\%'))) AND NOT (((CommandLine LIKE '%\\AppData\\Local\\Temp\\OpenOffice%' AND CommandLine LIKE '%Installation Files\\openoffice%'))))
