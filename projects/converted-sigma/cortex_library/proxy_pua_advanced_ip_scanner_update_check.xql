// Title: PUA - Advanced IP/Port Scanner Update Check
// ID: 1a9bb21a-1bb5-42d7-aa05-3219c7c8f47d
// Status: test
// Level: medium
// Author: Axel Olsson
// Date: 2022-08-14
// Tags: attack.discovery, attack.reconnaissance, attack.t1590
// Description: Detect the update check performed by Advanced IP/Port Scanner utilities.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (c-uri contains "/checkupdate.php" and (c-uri-query contains "lng=" and c-uri-query contains "ver=" and c-uri-query contains "beta=" and c-uri-query contains "type=" and c-uri-query contains "rmode=" and c-uri-query contains "product="))
