// Title: Windows Recovery Environment Disabled Via Reagentc
// ID: db1c21e4-cd66-4b4e-85ca-590f0780529c
// Status: experimental
// Level: medium
// Author: Daniel Koifman (KoifSec), Michael Vilshin
// Date: 2025-07-31
// Tags: attack.impact, attack.t1490
// Description: Detects attempts to disable windows recovery environment using Reagentc.
// ReAgentc.exe is a command-line tool in Windows used to manage the Windows Recovery Environment (WinRE).
// It allows users to enable, disable, and configure WinRE, which is used for troubleshooting and repairing common boot issues.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "/disable" OR CommandLine contains "-disable")) AND ((Image="*\\reagentc.exe") OR (OriginalFileName == "reagentc.exe")))
