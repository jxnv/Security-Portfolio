// Title: HackTool - UACMe Akagi Execution
// ID: d38d2fa4-98e6-4a24-aff1-410b0c9ad177
// Status: test
// Level: high
// Author: Christian Burkard (Nextron Systems), Florian Roth (Nextron Systems)
// Date: 2021-08-30
// Tags: attack.privilege-escalation, attack.t1548.002
// Description: Detects the execution of UACMe, a tool used for UAC bypasses, via default PE metadata
// Converted by: Sigma Universal SIEM/EDR CLI

(((Hashes: "*IMPHASH=767637C23BB42CD5D7397CF58B0BE688*" OR Hashes: "*IMPHASH=14C4E4C72BA075E9069EE67F39188AD8*" OR Hashes: "*IMPHASH=3C782813D4AFCE07BBFC5A9772ACDBDC*" OR Hashes: "*IMPHASH=7D010C6BB6A3726F327F7E239166D127*" OR Hashes: "*IMPHASH=89159BA4DD04E4CE5559F132A9964EB3*" OR Hashes: "*IMPHASH=6F33F4A5FC42B8CEC7314947BD13F30F*" OR Hashes: "*IMPHASH=5834ED4291BDEB928270428EBBAF7604*" OR Hashes: "*IMPHASH=5A8A8A43F25485E7EE1B201EDCBC7A38*" OR Hashes: "*IMPHASH=DC7D30B90B2D8ABF664FBED2B1B59894*" OR Hashes: "*IMPHASH=41923EA1F824FE63EA5BEB84DB7A3E74*" OR Hashes: "*IMPHASH=3DE09703C8E79ED2CA3F01074719906B*")) OR ((Image="*\\Akagi64.exe" OR Image="*\\Akagi.exe")) OR ((Product: "UACMe") OR ((Company: "REvol Corp" OR Company: "APT 92" OR Company: "UG North" OR Company: "Hazardous Environments" OR Company: "CD Project Rekt")) OR ((Description: "UACMe main module" OR Description: "Pentesting utility")) OR ((OriginalFileName: "Akagi.exe" OR OriginalFileName: "Akagi64.exe"))))
