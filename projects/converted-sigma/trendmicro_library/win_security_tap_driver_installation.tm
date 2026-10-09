// Title: Tap Driver Installation - Security
// ID: 9c8afa4d-0022-48f0-9456-3712466f9701
// Status: test
// Level: low
// Author: Daniil Yugoslavskiy, Ian Davis, oscd.community
// Date: 2019-10-24
// Tags: attack.exfiltration, attack.t1048
// Description: Detects the installation of a well-known TAP driver service. This could be a sign of potential preparation for data exfiltration using tunnelling techniques.
// Converted by: Sigma Universal SIEM/EDR CLI

(EventID: "4697" AND ServiceFileName: "*tap0901*")
