# Title: Azure Kubernetes Admission Controller
# ID: a61a3c56-4ce2-4351-a079-88ae4cbd2b58
# Status: test
# Level: medium
# Author: Austin Songer @austinsonger
# Date: 2021-11-25
# Tags: attack.privilege-escalation, attack.initial-access, attack.persistence, attack.stealth, attack.t1078, attack.credential-access, attack.t1552, attack.t1552.007
# Description: Identifies when an admission controller is executed in Azure Kubernetes.
# A Kubernetes Admission controller intercepts, and possibly modifies, requests to the Kubernetes API server.
# The behavior of this admission controller is determined by an admission webhook (MutatingAdmissionWebhook or ValidatingAdmissionWebhook) that the user deploys in the cluster.
# An adversary can use such webhooks as the MutatingAdmissionWebhook for obtaining persistence in the cluster.
# For example, attackers can intercept and modify the pod creation operations in the cluster and add their malicious container to every created pod.
# An adversary can use the webhook ValidatingAdmissionWebhook, which could be used to obtain access credentials.
# An adversary could use the webhook to intercept the requests to the API server, record secrets, and other sensitive information.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Azure Kubernetes Admission Controller
def rule(event):
    # Detection Logic:
    # ((operationName="MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/ADMISSIONREGISTRATION.K8S.IO*" OR operationName="MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS/ADMISSIONREGISTRATION.K8S.IO*") AND (operationName="*/MUTATINGWEBHOOKCONFIGURATIONS/WRITE" OR operationName="*/VALIDATINGWEBHOOKCONFIGURATIONS/WRITE"))
    return True

def title(event):
    return "Azure Kubernetes Admission Controller"

