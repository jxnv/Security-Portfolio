-- Title: PUA - Crassus Execution
-- ID: 2c32b543-1058-4808-91c6-5b31b8bed6c5
-- Status: test
-- Level: high
-- Author: pH-T (Nextron Systems)
-- Date: 2023-04-17
-- Tags: attack.discovery, attack.reconnaissance, attack.t1590.001
-- Description: Detects Crassus, a Windows privilege escalation discovery tool, based on PE metadata characteristics.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\Crassus.exe') OR (OriginalFileName = 'Crassus.exe') OR (Description ILIKE '%Crassus%'))
