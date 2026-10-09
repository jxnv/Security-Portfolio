-- Title: Suspicious Child Process Created as System
-- ID: 590a5f4c-6c8c-4f10-8307-89afe9453a9d
-- Status: test
-- Level: high
-- Author: Teymur Kheirkhabarov, Roberto Rodriguez (@Cyb3rWard0g), Open Threat Research (OTR)
-- Date: 2019-10-26
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1134.002
-- Description: Detection of child processes spawned with SYSTEM privileges by parents with LOCAL SERVICE or NETWORK SERVICE accounts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((ParentUser LIKE '%AUTHORI%' OR ParentUser LIKE '%AUTORI%') AND (ParentUser="*\\NETWORK SERVICE" OR ParentUser="*\\LOCAL SERVICE") AND (User LIKE '%AUTHORI%' OR User LIKE '%AUTORI%') AND (User="*\\SYSTEM" OR User="*\\Système" OR User="*\\СИСТЕМА") AND (IntegrityLevel = 'System' OR IntegrityLevel = 'S-1-16-16384')) AND NOT ((Image="*\\rundll32.exe" AND CommandLine LIKE '%DavSetCookie%')))
