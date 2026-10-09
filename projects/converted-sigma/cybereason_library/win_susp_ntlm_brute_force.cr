// Title: NTLM Brute Force
// ID: 9c8acf1a-cbf9-4db6-b63c-74baabe03e59
// Status: test
// Level: medium
// Author: Jerry Shockley '@jsh0x'
// Date: 2022-02-02
// Tags: attack.credential-access, attack.t1110
// Description: Detects common NTLM brute force device names
// Converted by: Sigma Universal SIEM/EDR CLI

((EventID == "8004") AND ((WorkstationName == "Rdesktop" OR WorkstationName == "Remmina" OR WorkstationName == "Freerdp" OR WorkstationName == "Windows7" OR WorkstationName == "Windows8" OR WorkstationName == "Windows2012" OR WorkstationName == "Windows2016" OR WorkstationName == "Windows2019")))
