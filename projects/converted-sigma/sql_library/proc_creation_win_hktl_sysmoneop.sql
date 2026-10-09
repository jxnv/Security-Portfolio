-- Title: HackTool - SysmonEOP Execution
-- ID: 8a7e90c5-fe6e-45dc-889e-057fe4378bd9
-- Status: test
-- Level: critical
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-12-04
-- Tags: cve.2022-41120, attack.t1068, attack.privilege-escalation
-- Description: Detects the execution of the PoC that can be used to exploit Sysmon CVE-2022-41120
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Hashes ILIKE '%IMPHASH=22F4089EB8ABA31E1BB162C6D9BF72E5%' OR Hashes ILIKE '%IMPHASH=5123FA4C4384D431CD0D893EEB49BBEC%')) OR (Image ILIKE '%\\SysmonEOP.exe'))
