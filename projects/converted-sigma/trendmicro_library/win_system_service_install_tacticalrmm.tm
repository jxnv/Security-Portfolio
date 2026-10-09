// Title: TacticalRMM Service Installation
// ID: 4bb79b62-ef12-4861-981d-2aab43fab642
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-11-28
// Tags: attack.command-and-control, attack.t1219.002
// Description: Detects a TacticalRMM service installation. Tactical RMM is a remote monitoring & management tool.
// Converted by: Sigma Universal SIEM/EDR CLI

((Provider_Name: "Service Control Manager" AND EventID: "7045") AND ((ImagePath: "*tacticalrmm.exe*") OR (ServiceName: "*TacticalRMM Agent Service*")))
