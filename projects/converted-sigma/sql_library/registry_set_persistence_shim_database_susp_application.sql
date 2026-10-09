-- Title: Suspicious Shim Database Patching Activity
-- ID: bf344fea-d947-4ef4-9192-34d008315d3a
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-08-01
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1546.011
-- Description: Detects installation of new shim databases that try to patch sections of known processes for potential process injection or persistence.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (TargetObject ILIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\%' AND (TargetObject ILIKE '%\\csrss.exe' OR TargetObject ILIKE '%\\dllhost.exe' OR TargetObject ILIKE '%\\explorer.exe' OR TargetObject ILIKE '%\\RuntimeBroker.exe' OR TargetObject ILIKE '%\\services.exe' OR TargetObject ILIKE '%\\sihost.exe' OR TargetObject ILIKE '%\\svchost.exe' OR TargetObject ILIKE '%\\taskhostw.exe' OR TargetObject ILIKE '%\\winlogon.exe' OR TargetObject ILIKE '%\\WmiPrvSe.exe'))
