// Title: Unsigned .node File Loaded
// ID: e5f5c693-52d7-4de5-88ae-afbfbce85595
// Status: experimental
// Level: medium
// Author: Jonathan Beierle (@hullabrian)
// Date: 2025-11-22
// Tags: attack.execution, attack.privilege-escalation, attack.persistence, attack.stealth, attack.t1129, attack.t1574.001, attack.t1036.005
// Description: Detects the loading of unsigned .node files.
// Adversaries may abuse a lack of .node integrity checking to execute arbitrary code inside of trusted applications such as Slack.
// .node files are native add-ons for Electron-based applications, which are commonly used for desktop applications like Slack, Discord, and Visual Studio Code.
// This technique has been observed in the DripLoader malware, which uses unsigned .node files to load malicious native code into Electron applications.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((ImageLoaded endswith ".node") and ((Signed = "false") or (SignatureStatus = "Unavailable"))) and not ((((action_process_image_path contains "C:\\Program Files (x86)\\" or action_process_image_path contains "C:\\Program Files\\" or action_process_image_path contains "\\AppData\\Local\\Programs\\") and action_process_image_path endswith "\\Evernote\\Evernote.exe" and ImageLoaded contains "\\Evernote\\resources\\app") or (action_process_image_path contains "\\Microsoft VS Code\\Code.exe" and ImageLoaded contains "\\Microsoft VS Code\\resources\\app\\node_modules") or (action_process_image_path endswith "\\Code.exe" and ImageLoaded contains ".vscode\\extensions\\ms-toolsai.jupyter-" and (ImageLoaded endswith "\\electron.napi.node" or ImageLoaded endswith "\\node.napi.glibc.node")))))
