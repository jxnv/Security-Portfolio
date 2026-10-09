-- Title: Potentially Suspicious Command Targeting Teams Sensitive Files
-- ID: d2eb17db-1d39-41dc-b57f-301f6512fa75
-- Status: test
-- Level: medium
-- Author: @SerkinValery
-- Date: 2022-09-16
-- Tags: attack.credential-access, attack.t1528
-- Description: Detects a commandline containing references to the Microsoft Teams database or cookies files from a process other than Teams.
-- The database might contain authentication tokens and other sensitive information about the logged in accounts.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%\\Microsoft\\Teams\\Cookies%' OR CommandLine ILIKE '%\\Microsoft\\Teams\\Local Storage\\leveldb%')) AND NOT ((Image ILIKE '%\\Microsoft\\Teams\\current\\Teams.exe')))
