// Title: Overwriting the File with Dev Zero or Null
// ID: 37222991-11e9-4b6d-8bdf-60fbe48f753e
// Status: stable
// Level: low
// Author: Jakob Weinzettl, oscd.community
// Date: 2019-10-23
// Tags: attack.impact, attack.t1485
// Description: Detects overwriting (effectively wiping/deleting) of a file.
// Converted by: Sigma Universal SIEM/EDR CLI

(type == "EXECVE" AND a0 contains "dd" AND (a1 contains "if=/dev/null" OR a1 contains "if=/dev/zero"))
