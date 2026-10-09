-- Title: Potentially Suspicious Command Executed Via Run Dialog Box - Registry
-- ID: a7df0e9e-91a5-459a-a003-4cde67c2ff5d
-- Status: test
-- Level: high
-- Author: Ahmed Farouk, Nasreddine Bencherchali
-- Date: 2024-11-01
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects execution of commands via the run dialog box on Windows by checking values of the "RunMRU" registry key.
-- This technique was seen being abused by threat actors to deceive users into pasting and executing malicious commands, often disguised as CAPTCHA verification steps.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetObject LIKE '%\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU%') AND ((((Details LIKE '%powershell%' OR Details LIKE '%pwsh%')) AND ((Details LIKE '% -e %' OR Details LIKE '% -ec %' OR Details LIKE '% -en %' OR Details LIKE '% -enc %' OR Details LIKE '% -enco%' OR Details LIKE '%ftp%' OR Details LIKE '%Hidden%' OR Details LIKE '%http%' OR Details LIKE '%iex%' OR Details LIKE '%Invoke-%'))) OR ((Details LIKE '%wmic%') AND ((Details LIKE '%shadowcopy%' OR Details LIKE '%process call create%')))))
