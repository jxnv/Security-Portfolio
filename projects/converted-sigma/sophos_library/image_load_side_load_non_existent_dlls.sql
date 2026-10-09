-- Title: Potential DLL Sideloading Of Non-Existent DLLs From System Folders
-- ID: 6b98b92b-4f00-4f62-b4fe-4d1920215771
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems), SBousseaden
-- Date: 2022-12-09
-- Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects loading of specific system DLL files that are usually not present on the system (or at least not in system directories) but may be loaded by legitimate processes, potentially indicating phantom DLL hijacking attempts.
-- Phantom DLL hijacking involves placing malicious DLLs with names of non-existent system binaries in locations where legitimate applications may search for them, leading to execution of the malicious DLLs.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((ImageLoaded ILIKE '%:\\Windows\\System32\\axeonoffhelper.dll' OR ImageLoaded ILIKE '%:\\Windows\\System32\\cdpsgshims.dll' OR ImageLoaded ILIKE '%:\\Windows\\System32\\oci.dll' OR ImageLoaded ILIKE '%:\\Windows\\System32\\offdmpsvc.dll' OR ImageLoaded ILIKE '%:\\Windows\\System32\\shellchromeapi.dll' OR ImageLoaded ILIKE '%:\\Windows\\System32\\TSMSISrv.dll' OR ImageLoaded ILIKE '%:\\Windows\\System32\\TSVIPSrv.dll' OR ImageLoaded ILIKE '%:\\Windows\\System32\\wbem\\wbemcomn.dll' OR ImageLoaded ILIKE '%:\\Windows\\System32\\WLBSCTRL.dll' OR ImageLoaded ILIKE '%:\\Windows\\System32\\wow64log.dll' OR ImageLoaded ILIKE '%:\\Windows\\System32\\WptsExtensions.dll')) AND NOT ((Signed = 'true' AND SignatureStatus = 'Valid' AND Signature = 'Microsoft Windows')))
