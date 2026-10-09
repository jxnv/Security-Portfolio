// Title: PUA - Advanced IP/Port Scanner Update Check
// ID: 1a9bb21a-1bb5-42d7-aa05-3219c7c8f47d
// Status: test
// Level: medium
// Author: Axel Olsson
// Date: 2022-08-14
// Tags: attack.discovery, attack.reconnaissance, attack.t1590
// Description: Detect the update check performed by Advanced IP/Port Scanner utilities.
// Converted by: Sigma Universal SIEM/EDR CLI

(c-uri: "*/checkupdate.php*" AND (c-uri-query: "*lng=*" AND c-uri-query: "*ver=*" AND c-uri-query: "*beta=*" AND c-uri-query: "*type=*" AND c-uri-query: "*rmode=*" AND c-uri-query: "*product=*"))
