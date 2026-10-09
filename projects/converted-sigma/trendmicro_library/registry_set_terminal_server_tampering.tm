// Title: RDP Sensitive Settings Changed
// ID: 3f6b7b62-61aa-45db-96bd-9c31b36b653c
// Status: test
// Level: high
// Author: Samir Bousseaden, David ANDRE, Roberto Rodriguez @Cyb3rWard0g, Nasreddine Bencherchali
// Date: 2022-08-06
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects tampering of RDP Terminal Service/Server sensitive settings.
// Such as allowing unauthorized users access to a system via the 'fAllowUnsolicited' or enabling RDP via 'fDenyTSConnections', etc.
// 
// Below is a list of registry keys/values that are monitored by this rule:
// 
// - Shadow: Used to enable Remote Desktop shadowing, which allows an administrator to view or control a user's session.
// - DisableRemoteDesktopAntiAlias: Disables anti-aliasing for remote desktop sessions.
// - DisableSecuritySettings: Disables certain security settings for Remote Desktop connections.
// - fAllowUnsolicited: Allows unsolicited remote assistance offers.
// - fAllowUnsolicitedFullControl: Allows unsolicited remote assistance offers with full control.
// - InitialProgram: Specifies a program to run automatically when a user logs on to a remote computer.
// - ServiceDll: Used in RDP hijacking techniques to specify a custom DLL to be loaded by the Terminal Services service.
// - SecurityLayer: Specifies the security layer used for RDP connections.
// Converted by: Sigma Universal SIEM/EDR CLI

((((TargetObject: "*\\Control\\Terminal Server\\*" OR TargetObject: "*\\Windows NT\\Terminal Services\\*") AND TargetObject="*\\Shadow" AND (Details: "DWORD (0x00000001)" OR Details: "DWORD (0x00000002)" OR Details: "DWORD (0x00000003)" OR Details: "DWORD (0x00000004)")) OR ((TargetObject: "*\\Control\\Terminal Server\\*" OR TargetObject: "*\\Windows NT\\Terminal Services\\*") AND (TargetObject="*\\DisableRemoteDesktopAntiAlias" OR TargetObject="*\\DisableSecuritySettings" OR TargetObject="*\\fAllowUnsolicited" OR TargetObject="*\\fAllowUnsolicitedFullControl") AND Details: "DWORD (0x00000001)") OR ((TargetObject: "*\\Control\\Terminal Server\\InitialProgram*" OR TargetObject: "*\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\InitialProgram*" OR TargetObject: "*\\services\\TermService\\Parameters\\ServiceDll*" OR TargetObject: "*\\Terminal Server\\WinStations\\RDP-Tcp\\SecurityLayer*" OR TargetObject: "*\\Windows NT\\Terminal Services\\InitialProgram*"))) AND NOT ((TargetObject="*\\SecurityLayer" AND Details: "DWORD (0x00000002)")))
