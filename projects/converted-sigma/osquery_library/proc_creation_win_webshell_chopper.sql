-- Title: Chopper Webshell Process Pattern
-- ID: fa3c117a-bc0d-416e-a31b-0c0e80653efb
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), MSTI (query)
-- Date: 2022-10-01
-- Tags: attack.persistence, attack.discovery, attack.t1505.003, attack.t1018, attack.t1033, attack.t1087
-- Description: Detects patterns found in process executions cause by China Chopper like tiny (ASPX) webshells
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%&ipconfig&echo%' OR CommandLine LIKE '%&quser&echo%' OR CommandLine LIKE '%&whoami&echo%' OR CommandLine LIKE '%&c:&echo%' OR CommandLine LIKE '%&cd&echo%' OR CommandLine LIKE '%&dir&echo%' OR CommandLine LIKE '%&echo [E]%' OR CommandLine LIKE '%&echo [S]%')) AND ((Image="*\\w3wp.exe") OR (ParentImage="*\\w3wp.exe")))
