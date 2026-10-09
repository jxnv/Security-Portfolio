-- Title: Suspicious PowerShell WindowStyle Option
-- ID: 313fbb0a-a341-4682-848d-6d6f8c4fab7c
-- Status: test
-- Level: medium
-- Author: frack113, Tim Shelton (fp AWS)
-- Date: 2021-10-20
-- Tags: attack.stealth, attack.t1564.003
-- Description: Adversaries may use hidden windows to conceal malicious activity from the plain sight of users.
-- In some cases, windows that would typically be displayed when an application carries out an operation can be hidden
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((ScriptBlockText ILIKE '%powershell%' AND ScriptBlockText ILIKE '%WindowStyle%' AND ScriptBlockText ILIKE '%Hidden%')) AND NOT (((ScriptBlockText ILIKE '%:\\Program Files\\Amazon\\WorkSpacesConfig\\Scripts\\%' AND ScriptBlockText ILIKE '%$PSScriptRoot\\Module\\WorkspaceScriptModule\\WorkspaceScriptModule%'))))
