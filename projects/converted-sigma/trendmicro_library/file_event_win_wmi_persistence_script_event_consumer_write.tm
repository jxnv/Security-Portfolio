// Title: WMI Persistence - Script Event Consumer File Write
// ID: 33f41cdd-35ac-4ba8-814b-c6a4244a1ad4
// Status: test
// Level: high
// Author: Thomas Patzke
// Date: 2018-03-07
// Tags: attack.privilege-escalation, attack.t1546.003, attack.persistence
// Description: Detects file writes of WMI script event consumer
// Converted by: Sigma Universal SIEM/EDR CLI

(Image: "C:\\WINDOWS\\system32\\wbem\\scrcons.exe")
