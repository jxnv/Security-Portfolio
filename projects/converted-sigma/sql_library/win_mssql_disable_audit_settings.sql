-- Title: MSSQL Disable Audit Settings
-- ID: 350dfb37-3706-4cdc-9e2e-5e24bc3a46df
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-13
-- Tags: attack.defense-impairment
-- Description: Detects when an attacker calls the "ALTER SERVER AUDIT" or "DROP SERVER AUDIT" transaction in order to delete or disable audit logs on the server
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (Provider_Name ILIKE '%MSSQL%' AND EventID = 33205 AND (Data ILIKE '%statement:ALTER SERVER AUDIT%' OR Data ILIKE '%statement:DROP SERVER AUDIT%'))
