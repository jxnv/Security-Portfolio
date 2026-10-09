-- Title: Uncommon Child Process Of Defaultpack.EXE
-- ID: b2309017-4235-44fe-b5af-b15363011957
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-12-31
-- Tags: attack.stealth, attack.t1218, attack.execution
-- Description: Detects uncommon child processes of "DefaultPack.EXE" binary as a proxy to launch other programs
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (ParentImage="*\\DefaultPack.exe")
