// Title: USB Device Plugged
// ID: 1a4bd6e3-4c6e-405d-a9a3-53a116e341d4
// Status: test
// Level: low
// Author: Florian Roth (Nextron Systems)
// Date: 2017-11-09
// Tags: attack.initial-access, attack.t1200
// Description: Detects plugged/unplugged USB devices
// Converted by: Sigma Universal SIEM/EDR CLI

((EventID: "2003" OR EventID: "2100" OR EventID: "2102"))
