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

dataset = xdr_data | filter (type = "EXECVE" and a0 = "xclip" and (a1 = "-selection" or a1 = "-sel") and (a2 = "clipboard" or a2 = "clip") and a3 = "-t" and a4 startswith "image/" and a5 = "-o")
