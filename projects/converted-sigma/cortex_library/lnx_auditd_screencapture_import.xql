// Title: Screen Capture with Import Tool
// ID: dbe4b9c5-c254-4258-9688-d6af0b7967fd
// Status: test
// Level: low
// Author: Pawel Mazur
// Date: 2021-09-21
// Tags: attack.collection, attack.t1113
// Description: Detects adversary creating screen capture of a desktop with Import Tool.
// Highly recommended using rule on servers, due to high usage of screenshot utilities on user workstations.
// ImageMagick must be installed.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((type = "EXECVE" and a0 = "import") and ((a1 = "-window" and a2 = "root" and (a3 endswith ".png" or a3 endswith ".jpg" or a3 endswith ".jpeg")) or ((a1 endswith ".png" or a1 endswith ".jpg" or a1 endswith ".jpeg"))))
