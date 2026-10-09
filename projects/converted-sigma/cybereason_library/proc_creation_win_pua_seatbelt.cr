// Title: PUA - Seatbelt Execution
// ID: 38646daa-e78f-4ace-9de0-55547b2d30da
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-18
// Tags: attack.discovery, attack.t1526, attack.t1087, attack.t1083
// Description: Detects the execution of the PUA/Recon tool Seatbelt via PE information of command line parameters
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\Seatbelt.exe") OR (OriginalFileName == "Seatbelt.exe") OR (Description == "Seatbelt") OR ((CommandLine contains " DpapiMasterKeys" OR CommandLine contains " InterestingProcesses" OR CommandLine contains " InterestingFiles" OR CommandLine contains " CertificateThumbprints" OR CommandLine contains " ChromiumBookmarks" OR CommandLine contains " ChromiumHistory" OR CommandLine contains " ChromiumPresence" OR CommandLine contains " CloudCredentials" OR CommandLine contains " CredEnum" OR CommandLine contains " CredGuard" OR CommandLine contains " FirefoxHistory" OR CommandLine contains " ProcessCreationEvents"))) OR (((CommandLine contains " -group=misc" OR CommandLine contains " -group=remote" OR CommandLine contains " -group=chromium" OR CommandLine contains " -group=slack" OR CommandLine contains " -group=system" OR CommandLine contains " -group=user" OR CommandLine contains " -group=all")) AND (CommandLine contains " -outputfile=")))
