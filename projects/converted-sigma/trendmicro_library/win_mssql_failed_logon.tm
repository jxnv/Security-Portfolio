// Title: MSSQL Server Failed Logon
// ID: 218d2855-2bba-4f61-9c85-81d0ea63ac71
// Status: test
// Level: low
// Author: Nasreddine Bencherchali (Nextron Systems), j4son
// Date: 2023-10-11
// Tags: attack.credential-access, attack.t1110
// Description: Detects failed logon attempts from clients to MSSQL server.
// Converted by: Sigma Universal SIEM/EDR CLI

(Provider_Name: "*MSSQL*" AND EventID: "18456")
