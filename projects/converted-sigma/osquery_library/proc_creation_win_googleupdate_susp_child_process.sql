-- Title: Potentially Suspicious GoogleUpdate Child Process
-- ID: 84b1ecf9-6eff-4004-bafb-bae5c0e251b2
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-15
-- Tags: attack.stealth
-- Description: Detects potentially suspicious child processes of "GoogleUpdate.exe"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((ParentImage="*\\GoogleUpdate.exe") AND NOT (((NOT Image=*) OR ((Image LIKE '%\\Google%') OR ((Image="*\\setup.exe" OR Image="*chrome_updater.exe" OR Image="*chrome_installer.exe"))))))
