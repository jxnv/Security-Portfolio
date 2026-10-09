-- Title: Password Protected ZIP File Opened (Suspicious Filenames)
-- ID: 54f0434b-726f-48a1-b2aa-067df14516e4
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-05-09
-- Tags: attack.command-and-control, attack.stealth, attack.t1027, attack.t1105, attack.t1036
-- Description: Detects the extraction of password protected ZIP archives with suspicious file names. See the filename variable for more details on which file has been opened.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((EventID = '5379' AND TargetName LIKE '%Microsoft_Windows_Shell_ZipFolder:filename%') AND ((TargetName LIKE '%invoice%' OR TargetName LIKE '%new order%' OR TargetName LIKE '%rechnung%' OR TargetName LIKE '%factura%' OR TargetName LIKE '%delivery%' OR TargetName LIKE '%purchase%' OR TargetName LIKE '%order%' OR TargetName LIKE '%payment%')))
