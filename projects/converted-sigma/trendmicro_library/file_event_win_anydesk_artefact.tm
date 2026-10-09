// Title: Anydesk Temporary Artefact
// ID: 0b9ad457-2554-44c1-82c2-d56a99c42377
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-02-11
// Tags: attack.command-and-control, attack.t1219.002
// Description: An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
// These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
// Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)
// Converted by: Sigma Universal SIEM/EDR CLI

((TargetFilename: "*\\AppData\\Roaming\\AnyDesk\\user.conf*" OR TargetFilename: "*\\AppData\\Roaming\\AnyDesk\\system.conf*"))
