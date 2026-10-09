-- Title: DotNET Assembly DLL Loaded Via Office Application
-- ID: ff0f2b05-09db-4095-b96d-1b75ca24894a
-- Status: test
-- Level: medium
-- Author: Antonlovesdnb
-- Date: 2020-02-19
-- Tags: attack.execution, attack.t1204.002
-- Description: Detects any assembly DLL being loaded by an Office Product
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((Image="*\\excel.exe" OR Image="*\\mspub.exe" OR Image="*\\onenote.exe" OR Image="*\\onenoteim.exe" OR Image="*\\outlook.exe" OR Image="*\\powerpnt.exe" OR Image="*\\winword.exe") AND ImageLoaded="C:\\Windows\\assembly\\*")
