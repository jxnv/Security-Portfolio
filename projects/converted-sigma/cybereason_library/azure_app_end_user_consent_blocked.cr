// Title: End User Consent Blocked
// ID: 7091372f-623c-4293-bc37-20c32b3492be
// Status: test
// Level: medium
// Author: Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow'
// Date: 2022-07-10
// Tags: attack.credential-access, attack.t1528
// Description: Detects when end user consent is blocked due to risk-based consent.
// Converted by: Sigma Universal SIEM/EDR CLI

(failure_status_reason == "Microsoft.online.Security.userConsentBlockedForRiskyAppsExceptions")
