-- Title: Disable Windows Firewall by Registry
-- ID: e78c408a-e2ea-43cd-b5ea-51975cf358c0
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-08-19
-- Tags: attack.defense-impairment, attack.t1686.003
-- Description: Detect set EnableFirewall to 0 to disable the Windows firewall
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((TargetObject ILIKE '%\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\StandardProfile\\EnableFirewall' OR TargetObject ILIKE '%\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\EnableFirewall') AND Details = 'DWORD (0x00000000)')
