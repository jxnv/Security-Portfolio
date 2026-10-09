// Title: Potential Base64 Decoded From Images
// ID: 09a910bf-f71f-4737-9c40-88880ba5913d
// Status: test
// Level: high
// Author: Joseliyo Sanchez, @Joseliyo_Jstnk
// Date: 2023-12-20
// Tags: attack.stealth, attack.t1140
// Description: Detects the use of tail to extract bytes at an offset from an image and then decode the base64 value to create a new file with the decoded content. The detected execution is a bash one-liner.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "base64" AND CommandLine contains "-d" AND CommandLine contains ">")) AND ((CommandLine contains ".avif" OR CommandLine contains ".gif" OR CommandLine contains ".jfif" OR CommandLine contains ".jpeg" OR CommandLine contains ".jpg" OR CommandLine contains ".pjp" OR CommandLine contains ".pjpeg" OR CommandLine contains ".png" OR CommandLine contains ".svg" OR CommandLine contains ".webp")) AND (Image="*/bash") AND ((CommandLine contains "tail" AND CommandLine contains "-c")))
