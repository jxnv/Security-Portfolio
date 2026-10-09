-- Title: Change the Fax Dll
-- ID: 9e3357ba-09d4-4fbd-a7c5-ad6386314513
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2022-07-17
-- Tags: attack.persistence, attack.defense-impairment, attack.t1112
-- Description: Detect possible persistence using Fax DLL load when service restart
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((TargetObject ILIKE '%\\Software\\Microsoft\\Fax\\Device Providers\\%' AND TargetObject ILIKE '%\\ImageName%')) AND NOT ((Details = '%systemroot%\\system32\\fxst30.dll')))
