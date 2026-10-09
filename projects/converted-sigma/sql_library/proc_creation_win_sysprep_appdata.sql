-- Title: Sysprep on AppData Folder
-- ID: d5b9ae7a-e6fc-405e-80ff-2ff9dcc64e7e
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2018-06-22
-- Tags: attack.execution, attack.t1059
-- Description: Detects suspicious sysprep process start with AppData folder as target (as used by Trojan Syndicasec in Thrip report by Symantec)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (Image ILIKE '%\\sysprep.exe' AND CommandLine ILIKE '%\\AppData\\%')
