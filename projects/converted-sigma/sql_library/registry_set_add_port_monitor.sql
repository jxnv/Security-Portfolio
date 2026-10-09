-- Title: Add Port Monitor Persistence in Registry
-- ID: 944e8941-f6f6-4ee8-ac05-1c224e923c0e
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-12-30
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1547.010
-- Description: Adversaries may use port monitors to run an attacker supplied DLL during system boot for persistence or privilege escalation.
-- A port monitor can be set through the AddMonitor API call to set a DLL to be loaded at startup.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((TargetObject ILIKE '%\\Control\\Print\\Monitors\\%' AND Details ILIKE '%.dll') AND NOT (((Image = 'C:\\Windows\\System32\\spoolsv.exe' AND TargetObject ILIKE '%\\Control\\Print\\Monitors\\CutePDF Writer Monitor v4.0\\Driver%' AND Details = 'cpwmon64_v40.dll' AND (User ILIKE '%AUTHORI%' OR User ILIKE '%AUTORI%')) OR (TargetObject ILIKE '%\\Control\\Print\\Monitors\\MONVNC\\Driver%') OR ((TargetObject ILIKE '%Control\\Print\\Environments\\%' AND TargetObject ILIKE '%\\Drivers\\%' AND TargetObject ILIKE '%\\VNC Printer%')))))
