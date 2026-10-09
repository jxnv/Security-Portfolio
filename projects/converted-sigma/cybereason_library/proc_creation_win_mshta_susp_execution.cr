// Title: MSHTA Execution with Suspicious File Extensions
// ID: cc7abbd0-762b-41e3-8a26-57ad50d2eea3
// Status: test
// Level: high
// Author: Diego Perez (@darkquassar), Markus Neis, Swisscom (Improve Rule), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2019-02-22
// Tags: attack.stealth, attack.t1140, attack.t1218.005, attack.execution, attack.t1059.007, cve.2020-1599
// Description: Detects execution of mshta.exe with file types that looks like they do not typically represent HTA (HTML Application) content,
// such as .png, .jpg, .zip, .pdf, and others, which are often polyglots. MSHTA is a legitimate Windows utility for executing HTML Applications
// containing VBScript or JScript. Threat actors often abuse this lolbin utility to download and
// execute malicious scripts disguised as benign files or hosted under misleading extensions to evade detection.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains ".7z" OR CommandLine contains ".avi" OR CommandLine contains ".bat" OR CommandLine contains ".bmp" OR CommandLine contains ".conf" OR CommandLine contains ".csv" OR CommandLine contains ".dll" OR CommandLine contains ".doc" OR CommandLine contains ".gif" OR CommandLine contains ".gz" OR CommandLine contains ".ini" OR CommandLine contains ".jpe" OR CommandLine contains ".jpg" OR CommandLine contains ".json" OR CommandLine contains ".lnk" OR CommandLine contains ".log" OR CommandLine contains ".mkv" OR CommandLine contains ".mp3" OR CommandLine contains ".mp4" OR CommandLine contains ".pdf" OR CommandLine contains ".png" OR CommandLine contains ".ppt" OR CommandLine contains ".rar" OR CommandLine contains ".rtf" OR CommandLine contains ".svg" OR CommandLine contains ".tar" OR CommandLine contains ".tmp" OR CommandLine contains ".txt" OR CommandLine contains ".xls" OR CommandLine contains ".xml" OR CommandLine contains ".yaml" OR CommandLine contains ".yml" OR CommandLine contains ".zip" OR CommandLine contains "vbscript")) AND ((Image="*\\mshta.exe") OR (OriginalFileName == "mshta.exe")))
