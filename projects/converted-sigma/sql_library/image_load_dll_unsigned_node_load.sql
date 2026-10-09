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

SELECT * FROM security_logs WHERE (((ImageLoaded ILIKE '%.node') AND ((Signed = 'false') OR (SignatureStatus = 'Unavailable'))) AND NOT ((((Image ILIKE '%C:\\Program Files (x86)\\%' OR Image ILIKE '%C:\\Program Files\\%' OR Image ILIKE '%\\AppData\\Local\\Programs\\%') AND Image ILIKE '%\\Evernote\\Evernote.exe' AND ImageLoaded ILIKE '%\\Evernote\\resources\\app%') OR (Image ILIKE '%\\Microsoft VS Code\\Code.exe%' AND ImageLoaded ILIKE '%\\Microsoft VS Code\\resources\\app\\node_modules%') OR (Image ILIKE '%\\Code.exe' AND ImageLoaded ILIKE '%.vscode\\extensions\\ms-toolsai.jupyter-%' AND (ImageLoaded ILIKE '%\\electron.napi.node' OR ImageLoaded ILIKE '%\\node.napi.glibc.node')))))
