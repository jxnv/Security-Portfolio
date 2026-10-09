// Title: Source Code Enumeration Detection by Keyword
// ID: 953d460b-f810-420a-97a2-cfca4c98e602
// Status: test
// Level: medium
// Author: James Ahearn
// Date: 2019-06-08
// Tags: attack.discovery, attack.t1083
// Description: Detects source code enumeration that use GET requests by keyword searches in URL strings
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (".git/")
