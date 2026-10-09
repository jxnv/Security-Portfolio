-- Title: Verclsid.exe Runs COM Object
-- ID: d06be4b9-8045-428b-a567-740a26d9db25
-- Status: test
-- Level: medium
-- Author: Victor Sergeev, oscd.community
-- Date: 2020-10-09
-- Tags: attack.stealth, attack.t1218
-- Description: Detects when verclsid.exe is used to run COM object via GUID
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%/S%' AND CommandLine LIKE '%/C%')) AND ((Image="*\\verclsid.exe") OR (OriginalFileName = 'verclsid.exe'))) AND NOT ((ParentImage="*C:\\Windows\\System32\\RuntimeBroker.exe" AND (CommandLine LIKE '%verclsid.exe\" /S /C {%' AND CommandLine LIKE '%} /I {%'))))
