-- Title: Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell Module
-- ID: f3c89218-8c3d-4ba9-9974-f1d8e6a1b4a6
-- Status: test
-- Level: high
-- Author: Timur Zinniatullin, oscd.community
-- Date: 2020-10-13
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via VAR++ LAUNCHER
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (Payload=regex("(?i)&&set.*(\\{\\d\\}){2,}\\\\\"\\s+?-f.*&&.*cmd.*/c"))
