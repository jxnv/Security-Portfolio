-- Title: Process Creation Using Sysnative Folder
-- ID: 3c1b5fb0-c72f-45ba-abd1-4d4c353144ab
-- Status: test
-- Level: medium
-- Author: Max Altgelt (Nextron Systems)
-- Date: 2022-08-23
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1055
-- Description: Detects process creation events that use the Sysnative folder (common for CobaltStrike spawns)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%:\\Windows\\Sysnative\\%') OR (Image LIKE '%:\\Windows\\Sysnative\\%')) AND NOT (((Image LIKE '%C:\\Windows\\Microsoft.NET\\Framework64\\v%' OR Image LIKE '%C:\\Windows\\Microsoft.NET\\Framework\\v%' OR Image LIKE '%C:\\Windows\\Microsoft.NET\\FrameworkArm\\v%' OR Image LIKE '%C:\\Windows\\Microsoft.NET\\FrameworkArm64\\v%') AND Image="*\\ngen.exe" AND CommandLine LIKE '%install%')) AND NOT (((CommandLine LIKE '%\"C:\\Windows\\sysnative\\cmd.exe\"%' AND CommandLine LIKE '%\\xampp\\%' AND CommandLine LIKE '%\\catalina_start.bat%'))))
