-- Title: Potential Provisioning Registry Key Abuse For Binary Proxy Execution
-- ID: 2a4b3e61-9d22-4e4a-b60f-6e8f0cde6f25
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel
-- Date: 2023-08-08
-- Tags: attack.stealth, attack.t1218
-- Description: Detects potential abuse of the provisioning registry key for indirect command execution through "Provlaunch.exe".
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (CommandLine ILIKE '%SOFTWARE\\Microsoft\\Provisioning\\Commands\\%')
