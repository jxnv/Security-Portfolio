// Title: Network Connection Initiated By IMEWDBLD.EXE
// ID: 8d7e392e-9b28-49e1-831d-5949c6281228
// Status: test
// Level: high
// Author: frack113
// Date: 2022-01-22
// Tags: attack.command-and-control, attack.t1105
// Description: Detects a network connection initiated by IMEWDBLD.EXE. This might indicate potential abuse of the utility as a LOLBIN in order to download arbitrary files or additional payloads.
// Converted by: Sigma Universal SIEM/EDR CLI

(Initiated: "true" AND Image="*\\IMEWDBLD.exe")
