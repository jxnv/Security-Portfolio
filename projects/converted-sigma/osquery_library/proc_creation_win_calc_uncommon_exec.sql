-- Title: Suspicious Calculator Usage
-- ID: 737e618a-a410-49b5-bec3-9e55ff7fbc15
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2019-02-09
-- Tags: attack.stealth, attack.t1036
-- Description: Detects suspicious use of 'calc.exe' with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%\\calc.exe %') OR ((Image="*\\calc.exe") AND NOT (((Image LIKE '%:\\Windows\\System32\\%' OR Image LIKE '%:\\Windows\\SysWOW64\\%' OR Image LIKE '%:\\Windows\\WinSxS\\%')))))
