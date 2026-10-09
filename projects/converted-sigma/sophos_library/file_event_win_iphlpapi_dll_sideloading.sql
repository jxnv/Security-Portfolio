-- Title: Malicious DLL File Dropped in the Teams or OneDrive Folder
-- ID: 1908fcc1-1b92-4272-8214-0fbaf2fa5163
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2022-08-12
-- Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects creation of a malicious DLL file in the location where the OneDrive or Team applications
-- Upon execution of the Teams or OneDrive application, the dropped malicious DLL file ("iphlpapi.dll") is sideloaded
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((TargetFilename ILIKE '%iphlpapi.dll%' AND TargetFilename ILIKE '%\\AppData\\Local\\Microsoft%'))
