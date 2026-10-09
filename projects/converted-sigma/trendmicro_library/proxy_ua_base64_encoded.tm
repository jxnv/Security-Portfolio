// Title: Suspicious Base64 Encoded User-Agent
// ID: d443095b-a221-4957-a2c4-cd1756c9b747
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-04
// Tags: attack.command-and-control, attack.t1071.001
// Description: Detects suspicious encoded User-Agent strings, as seen used by some malware.
// Converted by: Sigma Universal SIEM/EDR CLI

((c-useragent="Q2hyb21l*" OR c-useragent="QXBwbGVXZWJLaX*" OR c-useragent="RGFsdmlr*" OR c-useragent="TW96aWxsY*"))
