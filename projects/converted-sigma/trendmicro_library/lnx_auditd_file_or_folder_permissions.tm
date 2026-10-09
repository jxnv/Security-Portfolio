// Title: File or Folder Permissions Change
// ID: 74c01ace-0152-4094-8ae2-6fd776dd43e5
// Status: test
// Level: low
// Author: Jakob Weinzettl, oscd.community
// Date: 2019-09-23
// Tags: attack.defense-impairment, attack.t1222.002
// Description: Detects file and folder permission changes.
// Converted by: Sigma Universal SIEM/EDR CLI

(type: "EXECVE" AND (a0: "*chmod*" OR a0: "*chown*"))
