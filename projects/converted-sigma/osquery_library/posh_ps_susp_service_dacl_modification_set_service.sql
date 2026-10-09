-- Title: Suspicious Service DACL Modification Via Set-Service Cmdlet - PS
-- ID: 22d80745-6f2c-46da-826b-77adaededd74
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-10-24
-- Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.011
-- Description: Detects usage of the "Set-Service" powershell cmdlet to configure a new SecurityDescriptor that allows a service to be hidden from other utilities such as "sc.exe", "Get-Service"...etc. (Works only in powershell 7)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((ScriptBlockText LIKE '%-SecurityDescriptorSddl %' OR ScriptBlockText LIKE '%-sd %')) AND ((ScriptBlockText LIKE '%Set-Service %' AND ScriptBlockText LIKE '%D;;%') AND (ScriptBlockText LIKE '%;;;IU%' OR ScriptBlockText LIKE '%;;;SU%' OR ScriptBlockText LIKE '%;;;BA%' OR ScriptBlockText LIKE '%;;;SY%' OR ScriptBlockText LIKE '%;;;WD%')))
