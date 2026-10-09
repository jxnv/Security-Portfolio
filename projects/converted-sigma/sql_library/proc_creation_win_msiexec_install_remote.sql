-- Title: Suspicious Msiexec Quiet Install From Remote Location
-- ID: 8150732a-0c9d-4a99-82b9-9efb9b90c40c
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-10-28
-- Tags: attack.stealth, attack.t1218.007
-- Description: Detects usage of Msiexec.exe to install packages hosted remotely quietly
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((CommandLine ILIKE '%-i%' OR CommandLine ILIKE '%/i%' OR CommandLine ILIKE '%-package%' OR CommandLine ILIKE '%/package%' OR CommandLine ILIKE '%-a%' OR CommandLine ILIKE '%/a%' OR CommandLine ILIKE '%-j%' OR CommandLine ILIKE '%/j%')) AND ((Image ILIKE '%\\msiexec.exe') OR (OriginalFileName = 'msiexec.exe')) AND ((CommandLine ILIKE '%-q%' OR CommandLine ILIKE '%/q%')) AND ((CommandLine ILIKE '%http%' OR CommandLine ILIKE '%\\\\\\\\%'))) AND NOT (((CommandLine ILIKE '%\\AppData\\Local\\Temp\\OpenOffice%' AND CommandLine ILIKE '%Installation Files\\openoffice%'))))
