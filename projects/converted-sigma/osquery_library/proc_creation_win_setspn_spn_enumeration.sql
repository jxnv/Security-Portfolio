-- Title: Potential SPN Enumeration Via Setspn.EXE
-- ID: 1eeed653-dbc8-4187-ad0c-eeebb20e6599
-- Status: test
-- Level: medium
-- Author: Markus Neis, keepwatch
-- Date: 2018-11-14
-- Tags: attack.credential-access, attack.t1558.003
-- Description: Detects service principal name (SPN) enumeration used for Kerberoasting
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% -q %' OR CommandLine LIKE '% /q %')) AND ((Image="*\\setspn.exe") OR (OriginalFileName = 'setspn.exe') OR ((Description LIKE '%Query or reset the computer%' AND Description LIKE '%SPN attribute%'))))
