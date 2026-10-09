-- Title: Unsigned .node File Loaded
-- ID: e5f5c693-52d7-4de5-88ae-afbfbce85595
-- Status: experimental
-- Level: medium
-- Author: Jonathan Beierle (@hullabrian)
-- Date: 2025-11-22
-- Tags: attack.execution, attack.privilege-escalation, attack.persistence, attack.stealth, attack.t1129, attack.t1574.001, attack.t1036.005
-- Description: Detects the loading of unsigned .node files.
-- Adversaries may abuse a lack of .node integrity checking to execute arbitrary code inside of trusted applications such as Slack.
-- .node files are native add-ons for Electron-based applications, which are commonly used for desktop applications like Slack, Discord, and Visual Studio Code.
-- This technique has been observed in the DripLoader malware, which uses unsigned .node files to load malicious native code into Electron applications.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((ImageLoaded="*.node") AND ((Signed = 'false') OR (SignatureStatus = 'Unavailable'))) AND NOT ((((Image LIKE '%C:\\Program Files (x86)\\%' OR Image LIKE '%C:\\Program Files\\%' OR Image LIKE '%\\AppData\\Local\\Programs\\%') AND Image="*\\Evernote\\Evernote.exe" AND ImageLoaded LIKE '%\\Evernote\\resources\\app%') OR (Image LIKE '%\\Microsoft VS Code\\Code.exe%' AND ImageLoaded LIKE '%\\Microsoft VS Code\\resources\\app\\node_modules%') OR (Image="*\\Code.exe" AND ImageLoaded LIKE '%.vscode\\extensions\\ms-toolsai.jupyter-%' AND (ImageLoaded="*\\electron.napi.node" OR ImageLoaded="*\\node.napi.glibc.node")))))
