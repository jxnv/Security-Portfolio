// Title: Remote Utilities Host Service Install
// ID: 85cce894-dd8b-4427-a958-5cc47a4dc9b9
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-31
// Tags: attack.persistence
// Description: Detects Remote Utilities Host service installation on the target system.
// Converted by: Sigma Universal SIEM/EDR CLI

((Provider_Name: "Service Control Manager" AND EventID: "7045") AND (((ImagePath: "*\\rutserv.exe*" AND ImagePath: "*-service*")) OR (ServiceName: "Remote Utilities - Host")))
