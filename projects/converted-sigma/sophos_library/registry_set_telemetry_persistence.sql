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

SELECT * FROM process_journal WHERE ((TargetObject ILIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\TelemetryController\\%' AND TargetObject ILIKE '%\\Command' AND (Details ILIKE '%.bat%' OR Details ILIKE '%.bin%' OR Details ILIKE '%.cmd%' OR Details ILIKE '%.dat%' OR Details ILIKE '%.dll%' OR Details ILIKE '%.exe%' OR Details ILIKE '%.hta%' OR Details ILIKE '%.jar%' OR Details ILIKE '%.js%' OR Details ILIKE '%.msi%' OR Details ILIKE '%.ps%' OR Details ILIKE '%.sh%' OR Details ILIKE '%.vb%')) AND NOT (((Details ILIKE '%\\system32\\CompatTelRunner.exe%' OR Details ILIKE '%\\system32\\DeviceCensus.exe%'))))
