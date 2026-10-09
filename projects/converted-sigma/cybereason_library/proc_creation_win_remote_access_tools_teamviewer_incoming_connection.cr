// Title: Remote Access Tool - Team Viewer Session Started On Windows Host
// ID: ab70c354-d9ac-4e11-bbb6-ec8e3b153357
// Status: test
// Level: low
// Author: Josh Nickels, Qi Nan
// Date: 2024-03-11
// Tags: attack.persistence, attack.initial-access, attack.t1133
// Description: Detects the command line executed when TeamViewer starts a session started by a remote host.
// Once a connection has been started, an investigator can verify the connection details by viewing the "incoming_connections.txt" log file in the TeamViewer folder.
// Converted by: Sigma Universal SIEM/EDR CLI

(Image == "TeamViewer_Desktop.exe" AND ParentImage == "TeamViewer_Service.exe" AND CommandLine="*TeamViewer_Desktop.exe --IPCport 5939 --Module 1")
