This template uses Set-MDIConfiguration to create GPOs and add the recommended auditing settings for an MDI rollout. It sets the following configurations: 

AdvancedAuditPolicyDCs,DomainObjectAuditing,NTLMAuditing

This is essentially enough for a basic test lab, but other configurations are available if desired. For more information go here: https://learn.microsoft.com/en-us/powershell/module/defenderforidentity/set-mdiconfiguration?view=defenderforidentity-latest
