// Title: Suspicious Network Communication With IPFS
// ID: eb6c2004-1cef-427f-8885-9042974e5eb6
// Status: test
// Level: low
// Author: Gavin Knapp
// Date: 2023-03-16
// Tags: attack.collection, attack.credential-access, attack.t1056
// Description: Detects connections to interplanetary file system (IPFS) containing a user's email address which mirrors behaviours observed in recent phishing campaigns leveraging IPFS to host credential harvesting webpages.
// Converted by: Sigma Universal SIEM/EDR CLI

(cs-uri=regex("(?i)(ipfs\\.io/|ipfs\\.io\\s).+\\..+@.+\\.[a-z]+"))
