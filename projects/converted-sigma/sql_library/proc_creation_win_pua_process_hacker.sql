-- Title: PUA - Process Hacker Execution
-- ID: 811e0002-b13b-4a15-9d00-a613fce66e42
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-10-10
-- Tags: attack.discovery, attack.persistence, attack.privilege-escalation, attack.stealth, attack.t1622, attack.t1564, attack.t1543
-- Description: Detects the execution of Process Hacker based on binary metadata information (Image, Hash, Imphash, etc).
-- Process Hacker is a tool to view and manipulate processes, kernel options and other low level options.
-- Threat actors abused older vulnerable versions to manipulate system processes.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%\\ProcessHacker_%') OR (Image ILIKE '%\\ProcessHacker.exe') OR ((OriginalFileName = 'ProcessHacker.exe' OR OriginalFileName = 'Process Hacker')) OR (Description = 'Process Hacker') OR (Product = 'Process Hacker') OR ((Hashes ILIKE '%MD5=68F9B52895F4D34E74112F3129B3B00D%' OR Hashes ILIKE '%MD5=B365AF317AE730A67C936F21432B9C71%' OR Hashes ILIKE '%SHA1=A0BDFAC3CE1880B32FF9B696458327CE352E3B1D%' OR Hashes ILIKE '%SHA1=C5E2018BF7C0F314FED4FD7FE7E69FA2E648359E%' OR Hashes ILIKE '%SHA256=D4A0FE56316A2C45B9BA9AC1005363309A3EDC7ACF9E4DF64D326A0FF273E80F%' OR Hashes ILIKE '%SHA256=BD2C2CF0631D881ED382817AFCCE2B093F4E412FFB170A719E2762F250ABFEA4%' OR Hashes ILIKE '%IMPHASH=3695333C60DEDECDCAFF1590409AA462%' OR Hashes ILIKE '%IMPHASH=04DE0AD9C37EB7BD52043D2ECAC958DF%')))
