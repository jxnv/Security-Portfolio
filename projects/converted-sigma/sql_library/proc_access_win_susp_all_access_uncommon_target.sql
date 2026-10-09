-- Title: Uncommon Process Access Rights For Target Image
-- ID: a24e5861-c6ca-4fde-a93c-ba9256feddf0
-- Status: test
-- Level: low
-- Author: Nasreddine Bencherchali (Nextron Systems), frack113
-- Date: 2024-05-27
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1055.011
-- Description: Detects process access request to uncommon target images with a "PROCESS_ALL_ACCESS" access mask.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((TargetImage ILIKE '%\\calc.exe' OR TargetImage ILIKE '%\\calculator.exe' OR TargetImage ILIKE '%\\mspaint.exe' OR TargetImage ILIKE '%\\notepad.exe' OR TargetImage ILIKE '%\\ping.exe' OR TargetImage ILIKE '%\\wordpad.exe' OR TargetImage ILIKE '%\\write.exe') AND GrantedAccess = '0x1FFFFF')
