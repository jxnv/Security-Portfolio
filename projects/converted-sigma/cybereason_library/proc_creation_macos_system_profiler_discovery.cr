// Title: System Information Discovery Using System_Profiler
// ID: 4809c683-059b-4935-879d-36835986f8cf
// Status: test
// Level: medium
// Author: Stephen Lincoln `@slincoln_aiq` (AttackIQ)
// Date: 2024-01-02
// Tags: attack.discovery, attack.stealth, attack.t1082, attack.t1497.001
// Description: Detects the execution of "system_profiler" with specific "Data Types" that have been seen being used by threat actors and malware. It provides system hardware and software configuration information.
// This process is primarily used for system information discovery. However, "system_profiler" can also be used to determine if virtualization software is being run for defense evasion purposes.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "SPApplicationsDataType" OR CommandLine contains "SPHardwareDataType" OR CommandLine contains "SPNetworkDataType" OR CommandLine contains "SPUSBDataType")) AND ((Image="*/system_profiler") OR (CommandLine contains "system_profiler")))
