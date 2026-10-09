-- Title: LiveKD Driver Creation
-- ID: 16fe46bb-4f64-46aa-817d-ff7bec4a2352
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-16
-- Tags: attack.privilege-escalation, attack.stealth
-- Description: Detects the creation of the LiveKD driver, which is used for live kernel debugging
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (TargetFilename = 'C:\\Windows\\System32\\drivers\\LiveKdD.SYS' AND (Image ILIKE '%\\livekd.exe' OR Image ILIKE '%\\livek64.exe'))
