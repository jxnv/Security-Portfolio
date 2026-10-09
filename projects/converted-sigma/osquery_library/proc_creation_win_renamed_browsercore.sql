-- Title: Renamed BrowserCore.EXE Execution
-- ID: 8a4519e8-e64a-40b6-ae85-ba8ad2177559
-- Status: test
-- Level: high
-- Author: Max Altgelt (Nextron Systems)
-- Date: 2022-06-02
-- Tags: attack.credential-access, attack.stealth, attack.t1528, attack.t1036.003
-- Description: Detects process creation with a renamed BrowserCore.exe (used to extract Azure tokens)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((OriginalFileName = 'BrowserCore.exe') AND NOT ((Image="*\\BrowserCore.exe")))
