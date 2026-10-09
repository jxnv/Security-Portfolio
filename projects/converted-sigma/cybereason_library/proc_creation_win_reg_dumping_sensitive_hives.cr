// Title: Dumping of Sensitive Hives Via Reg.EXE
// ID: fd877b94-9bb5-4191-bb25-d79cbd93c167
// Status: test
// Level: high
// Author: Teymur Kheirkhabarov, Endgame, JHasenbusch, Daniil Yugoslavskiy, oscd.community, frack113
// Date: 2019-10-22
// Tags: attack.credential-access, attack.t1003.002, attack.t1003.004, attack.t1003.005, car.2013-07-001
// Description: Detects the usage of "reg.exe" in order to dump sensitive registry hives. This includes SAM, SYSTEM and SECURITY hives.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains " save " OR CommandLine contains " export " OR CommandLine contains " ˢave " OR CommandLine contains " eˣport ")) AND ((CommandLine contains "\\system" OR CommandLine contains "\\sam" OR CommandLine contains "\\security" OR CommandLine contains "\\ˢystem" OR CommandLine contains "\\syˢtem" OR CommandLine contains "\\ˢyˢtem" OR CommandLine contains "\\ˢam" OR CommandLine contains "\\ˢecurity")) AND ((CommandLine contains "hklm" OR CommandLine contains "hk˪m" OR CommandLine contains "hkey_local_machine" OR CommandLine contains "hkey_˪ocal_machine" OR CommandLine contains "hkey_loca˪_machine" OR CommandLine contains "hkey_˪oca˪_machine")) AND ((Image="*\\reg.exe") OR (OriginalFileName == "reg.exe")))
