// Title: Remote Access Tool - ScreenConnect Server Web Shell Execution
// ID: b19146a3-25d4-41b4-928b-1e2a92641b1b
// Status: test
// Level: high
// Author: Jason Rathbun (Blackpoint Cyber)
// Date: 2024-02-26
// Tags: attack.initial-access, attack.t1190
// Description: Detects potential web shell execution from the ScreenConnect server process.
// Converted by: Sigma Universal SIEM/EDR CLI

(ParentImage="*\\ScreenConnect.Service.exe" AND (Image="*\\cmd.exe" OR Image="*\\csc.exe"))
