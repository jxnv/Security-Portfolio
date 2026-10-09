-- Title: PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE
-- ID: 455b9d50-15a1-4b99-853f-8d37655a4c1b
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2021-12-13
-- Tags: attack.discovery, attack.t1087.002
-- Description: Detects active directory enumeration activity using known AdFind CLI flags
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%-sc admincountdmp%') OR (CommandLine LIKE '%-sc exchaddresses%') OR ((CommandLine LIKE '%lockoutduration%' OR CommandLine LIKE '%lockoutthreshold%' OR CommandLine LIKE '%lockoutobservationwindow%' OR CommandLine LIKE '%maxpwdage%' OR CommandLine LIKE '%minpwdage%' OR CommandLine LIKE '%minpwdlength%' OR CommandLine LIKE '%pwdhistorylength%' OR CommandLine LIKE '%pwdproperties%')))
