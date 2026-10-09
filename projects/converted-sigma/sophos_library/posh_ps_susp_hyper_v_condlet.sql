-- Title: Suspicious Hyper-V Cmdlets
-- ID: 42d36aa1-3240-4db0-8257-e0118dcdd9cd
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-04-09
-- Tags: attack.stealth, attack.t1564.006
-- Description: Adversaries may carry out malicious operations using a virtual instance to avoid detection
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ScriptBlockText ILIKE '%New-VM%' OR ScriptBlockText ILIKE '%Set-VMFirmware%' OR ScriptBlockText ILIKE '%Start-VM%'))
