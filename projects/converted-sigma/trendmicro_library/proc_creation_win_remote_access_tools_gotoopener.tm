// Title: Remote Access Tool - GoToAssist Execution
// ID: b6d98a4f-cef0-4abf-bbf6-24132854a83d
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-02-13
// Tags: attack.command-and-control, attack.t1219.002
// Description: An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
// These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
// Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)
// Converted by: Sigma Universal SIEM/EDR CLI

((Description: "GoTo Opener") OR (Product: "GoTo Opener") OR (Company: "LogMeIn, Inc."))
