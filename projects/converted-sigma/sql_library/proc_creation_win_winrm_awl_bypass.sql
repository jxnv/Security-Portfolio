-- Title: AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl
-- ID: 074e0ded-6ced-4ebd-8b4d-53f55908119d
-- Status: test
-- Level: medium
-- Author: Julia Fomina, oscd.community
-- Date: 2020-10-06
-- Tags: attack.stealth, attack.t1216
-- Description: Detects execution of attacker-controlled WsmPty.xsl or WsmTxt.xsl via winrm.vbs and copied cscript.exe (can be renamed)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '%winrm%') AND (((CommandLine ILIKE '%format:pretty%' OR CommandLine ILIKE '%format:\"pretty\"%' OR CommandLine ILIKE '%format:\"text\"%' OR CommandLine ILIKE '%format:text%')) AND NOT (((Image ILIKE 'C:\\Windows\\System32\\%' OR Image ILIKE 'C:\\Windows\\SysWOW64\\%')))))
