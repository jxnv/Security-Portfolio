-- Title: Potential Arbitrary File Download Using Office Application
-- ID: 4ae3e30b-b03f-43aa-87e3-b622f4048eed
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems), Beyu Denis, oscd.community
-- Date: 2022-05-17
-- Tags: attack.stealth, attack.t1202
-- Description: Detects potential arbitrary file download using a Microsoft Office application
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%http://%' OR CommandLine ILIKE '%https://%')) AND (((Image ILIKE '%\\EXCEL.EXE' OR Image ILIKE '%\\MSOXMLED.EXE' OR Image ILIKE '%\\POWERPNT.EXE' OR Image ILIKE '%\\WINWORD.exe')) OR ((OriginalFileName = 'Excel.exe' OR OriginalFileName = 'msoxmled.exe' OR OriginalFileName = 'POWERPNT.EXE' OR OriginalFileName = 'WinWord.exe'))))
