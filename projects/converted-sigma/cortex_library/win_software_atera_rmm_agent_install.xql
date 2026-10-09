// Title: Atera Agent Installation
// ID: 87261fb2-69d0-42fe-b9de-88c6b5f65a43
// Status: test
// Level: high
// Author: Bhabesh Raj
// Date: 2021-09-01
// Tags: attack.command-and-control, attack.t1219.002
// Description: Detects successful installation of Atera Remote Monitoring & Management (RMM) agent as recently found to be used by Conti operators
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (EventID = 1033 and Provider_Name = "MsiInstaller" and Message contains "AteraAgent")
