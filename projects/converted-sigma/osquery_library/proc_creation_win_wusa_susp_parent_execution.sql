-- Title: Wusa.EXE Executed By Parent Process Located In Suspicious Location
-- ID: ef64fc9c-a45e-43cc-8fd8-7d75d73b4c99
-- Status: test
-- Level: high
-- Author: X__Junior (Nextron Systems)
-- Date: 2023-11-26
-- Tags: attack.execution
-- Description: Detects execution of the "wusa.exe" (Windows Update Standalone Installer) utility by a parent process that is located in a suspicious location.
-- Attackers could instantiate an instance of "wusa.exe" in order to bypass User Account Control (UAC). They can duplicate the access token from "wusa.exe" to gain elevated privileges.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\wusa.exe") AND (((ParentImage LIKE '%:\\Perflogs\\%' OR ParentImage LIKE '%:\\Users\\Public\\%' OR ParentImage LIKE '%:\\Windows\\Temp\\%' OR ParentImage LIKE '%\\Appdata\\Local\\Temp\\%' OR ParentImage LIKE '%\\Temporary Internet%')) OR (((ParentImage LIKE '%:\\Users\\%' AND ParentImage LIKE '%\\Favorites\\%')) OR ((ParentImage LIKE '%:\\Users\\%' AND ParentImage LIKE '%\\Favourites\\%')) OR ((ParentImage LIKE '%:\\Users\\%' AND ParentImage LIKE '%\\Contacts\\%')) OR ((ParentImage LIKE '%:\\Users\\%' AND ParentImage LIKE '%\\Pictures\\%')))) AND NOT ((CommandLine LIKE '%.msu%')))
