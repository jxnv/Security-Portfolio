-- Title: Potential Suspicious Registry File Imported Via Reg.EXE
-- ID: 62e0298b-e994-4189-bc87-bc699aa62d97
-- Status: test
-- Level: medium
-- Author: frack113, Nasreddine Bencherchali
-- Date: 2022-08-01
-- Tags: attack.persistence, attack.defense-impairment, attack.t1112
-- Description: Detects the import of '.reg' files from suspicious paths using the 'reg.exe' utility
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '% import %') AND ((Image ILIKE '%\\reg.exe') OR (OriginalFileName = 'reg.exe')) AND ((CommandLine ILIKE '%C:\\Users\\%' OR CommandLine ILIKE '%%temp%%' OR CommandLine ILIKE '%%tmp%%' OR CommandLine ILIKE '%%appdata%%' OR CommandLine ILIKE '%\\AppData\\Local\\Temp\\%' OR CommandLine ILIKE '%C:\\Windows\\Temp\\%' OR CommandLine ILIKE '%C:\\ProgramData\\%')))
