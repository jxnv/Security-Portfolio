-- Title: Chopper Webshell Process Pattern
-- ID: fa3c117a-bc0d-416e-a31b-0c0e80653efb
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), MSTI (query)
-- Date: 2022-10-01
-- Tags: attack.persistence, attack.discovery, attack.t1505.003, attack.t1018, attack.t1033, attack.t1087
-- Description: Detects patterns found in process executions cause by China Chopper like tiny (ASPX) webshells
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%&ipconfig&echo%' OR CommandLine ILIKE '%&quser&echo%' OR CommandLine ILIKE '%&whoami&echo%' OR CommandLine ILIKE '%&c:&echo%' OR CommandLine ILIKE '%&cd&echo%' OR CommandLine ILIKE '%&dir&echo%' OR CommandLine ILIKE '%&echo [E]%' OR CommandLine ILIKE '%&echo [S]%')) AND ((Image ILIKE '%\\w3wp.exe') OR (ParentImage ILIKE '%\\w3wp.exe')))
