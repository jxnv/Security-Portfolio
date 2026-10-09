// Title: CA Policy Removed by Non Approved Actor
// ID: 26e7c5e2-6545-481e-b7e6-050143459635
// Status: test
// Level: medium
// Author: Corissa Koopmans, '@corissalea'
// Date: 2022-07-19
// Tags: attack.privilege-escalation, attack.credential-access, attack.persistence, attack.defense-impairment, attack.t1548, attack.t1556
// Description: Monitor and alert on conditional access changes where non approved actor removed CA Policy.
// Converted by: Sigma Universal SIEM/EDR CLI

(properties.message == "Delete conditional access policy")
