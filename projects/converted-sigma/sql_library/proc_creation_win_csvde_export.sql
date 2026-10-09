-- Title: Active Directory Structure Export Via Csvde.EXE
-- ID: e5d36acd-acb4-4c6f-a13f-9eb203d50099
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-03-14
-- Tags: attack.exfiltration, attack.discovery, attack.t1087.002
-- Description: Detects the execution of "csvde.exe" in order to export organizational Active Directory structure.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((Image ILIKE '%\\csvde.exe') OR (OriginalFileName = 'csvde.exe')) AND (CommandLine ILIKE '% -f%')) AND NOT ((CommandLine ILIKE '% -i%')))
