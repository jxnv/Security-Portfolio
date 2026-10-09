-- Title: Potential Registry Persistence Attempt Via Windows Telemetry
-- ID: 73a883d0-0348-4be4-a8d8-51031c2564f8
-- Status: test
-- Level: high
-- Author: Lednyov Alexey, oscd.community, Sreeman
-- Date: 2020-10-16
-- Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005
-- Description: Detects potential persistence behavior using the windows telemetry registry key.
-- Windows telemetry makes use of the binary CompatTelRunner.exe to run a variety of commands and perform the actual telemetry collections.
-- This binary was created to be easily extensible, and to that end, it relies on the registry to instruct on which commands to run.
-- The problem is, it will run any arbitrary command without restriction of location or type.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetObject LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\TelemetryController\\%' AND TargetObject="*\\Command" AND (Details LIKE '%.bat%' OR Details LIKE '%.bin%' OR Details LIKE '%.cmd%' OR Details LIKE '%.dat%' OR Details LIKE '%.dll%' OR Details LIKE '%.exe%' OR Details LIKE '%.hta%' OR Details LIKE '%.jar%' OR Details LIKE '%.js%' OR Details LIKE '%.msi%' OR Details LIKE '%.ps%' OR Details LIKE '%.sh%' OR Details LIKE '%.vb%')) AND NOT (((Details LIKE '%\\system32\\CompatTelRunner.exe%' OR Details LIKE '%\\system32\\DeviceCensus.exe%'))))
