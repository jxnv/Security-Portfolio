-- Title: PSExec and WMI Process Creations Block
-- ID: 97b9ce1e-c5ab-11ea-87d0-0242ac130003
-- Status: test
-- Level: high
-- Author: Bhabesh Raj
-- Date: 2020-07-14
-- Tags: attack.execution, attack.lateral-movement, attack.t1047, attack.t1569.002
-- Description: Detects blocking of process creations originating from PSExec and WMI commands
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (EventID = '1121' AND (ProcessName="*\\wmiprvse.exe" OR ProcessName="*\\psexesvc.exe"))
