// Title: AWS KMS Imported Key Material Usage
// ID: 1279262f-1464-422f-ac0d-5b545320c526
// Status: experimental
// Level: high
// Author: toopricey
// Date: 2025-10-18
// Tags: attack.impact, attack.t1486, attack.resource-development, attack.t1608.003
// Description: Detects the import or deletion of key material in AWS KMS, which can be used as part of ransomware attacks. This activity is uncommon and provides a high certainty signal.
// Converted by: Sigma Universal SIEM/EDR CLI

(eventSource == "kms.amazonaws.com" AND (eventName == "ImportKeyMaterial" OR eventName == "DeleteImportedKeyMaterial"))
