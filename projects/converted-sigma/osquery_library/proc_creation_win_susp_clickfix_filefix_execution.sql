-- Title: Suspicious ClickFix/FileFix Execution Pattern
-- ID: d487ed4a-fd24-436d-a0b2-f4e95f7b2635
-- Status: experimental
-- Level: high
-- Author: montysecurity, Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-11-19
-- Tags: attack.execution, attack.t1204.001, attack.t1204.004
-- Description: Detects suspicious execution patterns where users are tricked into running malicious commands via clipboard manipulation, either through the Windows Run dialog (ClickFix) or File Explorer address bar (FileFix).
-- Attackers leverage social engineering campaigns—such as fake CAPTCHA challenges or urgent alerts—encouraging victims to paste clipboard contents, often executing mshta.exe, powershell.exe, or similar commands to infect systems.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%account%' OR CommandLine LIKE '%anti-bot%' OR CommandLine LIKE '%botcheck%' OR CommandLine LIKE '%captcha%' OR CommandLine LIKE '%challenge%' OR CommandLine LIKE '%confirmation%' OR CommandLine LIKE '%fraud%' OR CommandLine LIKE '%human%' OR CommandLine LIKE '%identification%' OR CommandLine LIKE '%identificator%' OR CommandLine LIKE '%identity%' OR CommandLine LIKE '%robot%' OR CommandLine LIKE '%validation%' OR CommandLine LIKE '%verification%' OR CommandLine LIKE '%verify%')) AND (ParentImage="*\\explorer.exe" AND CommandLine LIKE '%#%'))
