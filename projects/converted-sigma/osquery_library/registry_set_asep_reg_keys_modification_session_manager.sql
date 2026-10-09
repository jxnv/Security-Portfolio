-- Title: Session Manager Autorun Keys Modification
-- ID: 046218bd-e0d8-4113-a3c3-895a12b2b298
-- Status: test
-- Level: medium
-- Author: Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
-- Date: 2019-10-25
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001, attack.t1546.009
-- Description: Detects modification of autostart extensibility point (ASEP) in registry.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetObject LIKE '%\\System\\CurrentControlSet\\Control\\Session Manager%') AND ((TargetObject LIKE '%\\SetupExecute%' OR TargetObject LIKE '%\\S0InitialCommand%' OR TargetObject LIKE '%\\KnownDlls%' OR TargetObject LIKE '%\\Execute%' OR TargetObject LIKE '%\\BootExecute%' OR TargetObject LIKE '%\\AppCertDlls%')) AND NOT ((Details = '(Empty)')))
