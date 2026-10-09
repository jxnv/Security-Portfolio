// Title: Azure New CloudShell Created
// ID: 72af37e2-ec32-47dc-992b-bc288a2708cb
// Status: test
// Level: medium
// Author: Austin Songer
// Date: 2021-09-21
// Tags: attack.execution, attack.t1059
// Description: Identifies when a new cloudshell is created inside of Azure portal.
// Converted by: Sigma Universal SIEM/EDR CLI

(operationName == "MICROSOFT.PORTAL/CONSOLES/WRITE")
