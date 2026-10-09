-- Title: Indirect Command Execution By Program Compatibility Wizard
-- ID: b97cd4b1-30b8-4a9d-bd72-6293928d52bc
-- Status: test
-- Level: low
-- Author: A. Sungurov , oscd.community
-- Date: 2020-10-12
-- Tags: attack.stealth, attack.t1218, attack.execution
-- Description: Detect indirect command execution via Program Compatibility Assistant pcwrun.exe
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (ParentImage ILIKE '%\\pcwrun.exe')
