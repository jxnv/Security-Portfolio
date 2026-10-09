-- Title: UAC Bypass Using WOW64 Logger DLL Hijack
-- ID: 4f6c43e2-f989-4ea5-bcd8-843b49a0317c
-- Status: test
-- Level: high
-- Author: Christian Burkard (Nextron Systems)
-- Date: 2021-08-23
-- Tags: attack.privilege-escalation, attack.t1548.002
-- Description: Detects the pattern of UAC Bypass using a WoW64 logger DLL hijack (UACMe 30)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (SourceImage ILIKE '%:\\Windows\\SysWOW64\\%' AND GrantedAccess = '0x1fffff' AND CallTrace ILIKE 'UNKNOWN(0000000000000000)|UNKNOWN(0000000000000000)|%')
