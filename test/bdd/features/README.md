# Actors


## 1. VCS Service Provider

### AWS Cognito

    UserPool
        ...
        ...
        # users for example issuer org
        tuu1 (test unitversity admin user)
            custom:tenant-id = test-university-1

        tuu2 (test unitversity admin user)
            custom:tenant-id = test-university-1

        # users for example verifier org
        teu1 (test employer admin user)
            custom:tenant-id = test-employer-1

        teu2 (test employer admin user)
            custom:tenant-id = test-employer-1


## 2. TestUniversity (Example Issuer Org)

### Organization Info
    OrganizationId (TenantId): test-university-1

    Admin Users
        tuu1 (authorized person from the university org to create/manage profiles)
        tuu2 (authorized person from the university org to create/manage profiles)
  
### OIDC configuration
    OIDC Config [
        ...,
        ...,

        # vcs client OIDC entry
        {
            # created and shared with VCS
            # for vcs to be able to communciate to this Organization
            vcs_client related OIDC information
        }
    ]

### Profiles
    tuu1	-> Profile-11, Profile-12, ...
	tuu2	-> Profile-21, Profile-22, ...


## 3. TestEmployer (Example Verifier Org)

### Organization Info
    OrganizationId (TenantId): test-employer-1

    Admin Users
        teu1 (authorized person from the employer org to create/manage profiles)
        teu2 (authorized person from the employer org to create/manage profiles)

### Profiles
    teu1	-> Profile-11, Profile-12, ...
	teu2	-> Profile-21, Profile-22, ...