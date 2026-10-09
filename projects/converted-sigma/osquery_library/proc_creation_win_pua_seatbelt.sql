-- Title: PUA - Seatbelt Execution
-- ID: 38646daa-e78f-4ace-9de0-55547b2d30da
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-10-18
-- Tags: attack.discovery, attack.t1526, attack.t1087, attack.t1083
-- Description: Detects the execution of the PUA/Recon tool Seatbelt via PE information of command line parameters
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\Seatbelt.exe") OR (OriginalFileName = 'Seatbelt.exe') OR (Description = 'Seatbelt') OR ((CommandLine LIKE '% DpapiMasterKeys%' OR CommandLine LIKE '% InterestingProcesses%' OR CommandLine LIKE '% InterestingFiles%' OR CommandLine LIKE '% CertificateThumbprints%' OR CommandLine LIKE '% ChromiumBookmarks%' OR CommandLine LIKE '% ChromiumHistory%' OR CommandLine LIKE '% ChromiumPresence%' OR CommandLine LIKE '% CloudCredentials%' OR CommandLine LIKE '% CredEnum%' OR CommandLine LIKE '% CredGuard%' OR CommandLine LIKE '% FirefoxHistory%' OR CommandLine LIKE '% ProcessCreationEvents%'))) OR (((CommandLine LIKE '% -group=misc%' OR CommandLine LIKE '% -group=remote%' OR CommandLine LIKE '% -group=chromium%' OR CommandLine LIKE '% -group=slack%' OR CommandLine LIKE '% -group=system%' OR CommandLine LIKE '% -group=user%' OR CommandLine LIKE '% -group=all%')) AND (CommandLine LIKE '% -outputfile=%')))
