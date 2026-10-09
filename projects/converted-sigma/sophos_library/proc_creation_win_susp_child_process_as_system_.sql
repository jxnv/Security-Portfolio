-- Title: Suspicious Child Process Created as System
-- ID: 590a5f4c-6c8c-4f10-8307-89afe9453a9d
-- Status: test
-- Level: high
-- Author: Teymur Kheirkhabarov, Roberto Rodriguez (@Cyb3rWard0g), Open Threat Research (OTR)
-- Date: 2019-10-26
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1134.002
-- Description: Detection of child processes spawned with SYSTEM privileges by parents with LOCAL SERVICE or NETWORK SERVICE accounts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((ParentUser ILIKE '%AUTHORI%' OR ParentUser ILIKE '%AUTORI%') AND (ParentUser ILIKE '%\\NETWORK SERVICE' OR ParentUser ILIKE '%\\LOCAL SERVICE') AND (User ILIKE '%AUTHORI%' OR User ILIKE '%AUTORI%') AND (User ILIKE '%\\SYSTEM' OR User ILIKE '%\\Système' OR User ILIKE '%\\СИСТЕМА') AND (IntegrityLevel = 'System' OR IntegrityLevel = 'S-1-16-16384')) AND NOT ((Image ILIKE '%\\rundll32.exe' AND CommandLine ILIKE '%DavSetCookie%')))
