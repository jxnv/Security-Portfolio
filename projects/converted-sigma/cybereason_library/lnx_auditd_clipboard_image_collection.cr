// Title: Clipboard Collection of Image Data with Xclip Tool
// ID: f200dc3f-b219-425d-a17e-c38467364816
// Status: test
// Level: low
// Author: Pawel Mazur
// Date: 2021-10-01
// Tags: attack.collection, attack.t1115
// Description: Detects attempts to collect image data stored in the clipboard from users with the usage of xclip tool.
// Xclip has to be installed.
// Highly recommended using rule on servers, due to high usage of clipboard utilities on user workstations.
// Converted by: Sigma Universal SIEM/EDR CLI

(type == "EXECVE" AND a0 == "xclip" AND (a1 == "-selection" OR a1 == "-sel") AND (a2 == "clipboard" OR a2 == "clip") AND a3 == "-t" AND a4="image/*" AND a5 == "-o")
