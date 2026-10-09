// Title: Remove Immutable File Attribute - Auditd
// ID: a5b977d6-8a81-4475-91b9-49dbfcd941f7
// Status: test
// Level: medium
// Author: Jakob Weinzettl, oscd.community
// Date: 2019-09-23
// Tags: attack.defense-impairment, attack.t1222.002
// Description: Detects removing immutable file attribute.
// Converted by: Sigma Universal SIEM/EDR CLI

(type: "EXECVE" AND a0: "*chattr*" AND a1: "*-i*")
