-- Title: Invoke-Obfuscation Via Stdin - Security
-- ID: 80b708f3-d034-40e4-a6c8-d23b7a7db3d1
-- Status: test
-- Level: high
-- Author: Nikita Nazarov, oscd.community
-- Date: 2020-10-12
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via Stdin in Scripts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (EventID = '4697' AND (ServiceFileName LIKE '%set%' AND ServiceFileName LIKE '%&&%') AND (ServiceFileName LIKE '%environment%' OR ServiceFileName LIKE '%invoke%' OR ServiceFileName LIKE '%${input)%'))
