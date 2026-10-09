-- Title: Potential DLL Sideloading Via DeviceEnroller.EXE
-- ID: e173ad47-4388-4012-ae62-bd13f71c18a8
-- Status: test
-- Level: medium
-- Author: @gott_cyber
-- Date: 2022-08-29
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects the use of the PhoneDeepLink parameter to potentially sideload a DLL file that does not exist. This non-existent DLL file is named "ShellChromeAPI.dll".
-- Adversaries can drop their own renamed DLL and execute it via DeviceEnroller.exe using this parameter
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '%/PhoneDeepLink%') AND ((Image ILIKE '%\\deviceenroller.exe') OR (OriginalFileName = 'deviceenroller.exe')))
