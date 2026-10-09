// Title: Potential DLL Sideloading Via JsSchHlp
// ID: 68654bf0-4412-43d5-bfe8-5eaa393cd939
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-12-14
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects potential DLL sideloading using JUSTSYSTEMS Japanese word processor
// Converted by: Sigma Universal SIEM/EDR CLI

((ImageLoaded="*\\JSESPR.dll") AND NOT ((ImageLoaded="C:\\Program Files\\Common Files\\Justsystem\\JsSchHlp\\*")))
