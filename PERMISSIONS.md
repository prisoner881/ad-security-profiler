# Setting up access for the FortifyData AD audit collector

This guide is for your Active Directory and Entra ID administrators. It
explains what the collector needs to read your directory, and how to set it
up. The collector runs unattended in your network, and only ever reads.

## 1. What the collector needs

| What | Used by | Needed |
|---|---|---|
| An **AD service account** (section 2) | `adprofiler.py`, Active Directory and Group Policy collection | Always |
| An **Entra ID App Registration** (section 3) | `entra_graph_collector.py`, Entra ID collection | Only if Entra ID is to be assessed |
| **Network access** (section 4) | the collector host | Always |

The collector never writes to Active Directory or Entra ID. It never
stores passwords, LAPS passwords, gMSA passwords, KDS root keys or the AD
FS key, and it does not try to read them.

## 2. The Active Directory service account

### 2.1 What the account is

The account is a dedicated, ordinary domain user:
- **Groups:** only *Domain Users*. Do not add it to Domain Admins or any
  other privileged group. It does not need them. A privileged collection
  account would also make some findings wrong; for example, the AD FS key
  would be reported as readable.
- **Delegations:** two narrow read delegations (section 2.3) that an
  ordinary user does not have by default.
- **Sign-in method:** the collector signs in with a username and password
  (LDAP simple bind). A group Managed Service Account (gMSA) cannot be used
  for this.
- **No logon rights:** it never logs on interactively, as a service or as
  a batch job.

### 2.2 Create the account

In **Active Directory Users and Computers**, in the OU where you keep
service accounts:

1. **New → User.**
   - **Logon name:** for example `svc_adaudit`.
   - **UPN suffix:** keep the domain's own DNS name, for example
     `svc_adaudit@corp.example.com`, not an alternative suffix. The Group
     Policy step takes the domain from it.
2. **Password:** a long random one, at least 25 characters.
   - Clear *User must change password at next logon*.
   - Either let the password expire on your normal schedule and update the
     collector when you change it (section 5.3), or set *Password never
     expires* if your service-account policy allows it.
3. **Account tab:**
   - **Set:** *Account is sensitive and cannot be delegated*.
   - **Leave clear:** *Smart card is required for interactive logon*.
   - **Logon hours and "Log On To":** leave unrestricted.
4. **Do not add the account to Protected Users.** Its members cannot use
   NTLM, which the Group Policy (SYSVOL) step uses by default.

Or with PowerShell (ActiveDirectory module):

```powershell
New-ADUser -Name "svc_adaudit" -SamAccountName "svc_adaudit" `
    -UserPrincipalName "svc_adaudit@corp.example.com" `
    -Path "OU=Service Accounts,DC=corp,DC=example,DC=com" `
    -Description "FortifyData AD audit collector (read-only)" `
    -AccountPassword (Read-Host -AsSecureString "Password") `
    -Enabled $true -AccountNotDelegated $true
```

**Optional hardening.** Through Group Policy on the domain controllers,
add the account to *Deny log on locally* and *Deny log on through Remote
Desktop Services*. The account must keep *Access this computer from the
network*; by default that is granted to Authenticated Users on domain
controllers.

### 2.3 The two delegations an ordinary user does not have

By default every domain user can read almost everything the collector
needs. That covers users, groups, computers, permissions (ACLs), trusts,
the password policy, AD CS, DNS zones, sites, the schema and Group Policy
files.

Two places are closed to ordinary users. AD does not refuse the read; it
returns nothing. So **without these delegations the collection still
succeeds, but its results are silently incomplete.** A *Domain Admin*
grants each one once per domain. Replace `DC=corp,DC=example,DC=com` and
`CORP\svc_adaudit` with your own values.

**A. Deleted Objects.** The collector learns from this container which
users, groups and computers were deleted. Without it, deleted accounts are
never recorded as deleted and are reported indefinitely. This is
Microsoft's documented method (KB 892806). The container is not visible in
the AD Users and Computers console, so it is done with `dsacls`, in an
elevated command prompt:

```
dsacls "CN=Deleted Objects,DC=corp,DC=example,DC=com" /takeownership
dsacls "CN=Deleted Objects,DC=corp,DC=example,DC=com" /G "CORP\svc_adaudit:LCRP"
```

`LC` is List Contents and `RP` is Read Property. Nothing else is granted:
the account cannot restore or change deleted objects.

**B. Fine-Grained Password Policies (password settings objects).** By
default only Domain Admins can read them. Without this delegation, every
user is assessed against the default domain password policy, even when a
stricter or weaker fine-grained policy applies.

```
dsacls "CN=Password Settings Container,CN=System,DC=corp,DC=example,DC=com" /I:T /G "CORP\svc_adaudit:GR"
```

Or in **AD Users and Computers**:
1. Select **View → Advanced Features**.
2. Open **System → Password Settings Container → Properties → Security →
   Advanced → Add**.
3. Select the account, *Applies to: This object and all descendant
   objects*, and the **Read** permission.

**Check both, as the service account:**

```powershell
$c = Get-Credential "CORP\svc_adaudit"
# A: should be more than 0 in any domain where something was ever deleted
(Get-ADObject -Credential $c -IncludeDeletedObjects -Filter 'isDeleted -eq $true' `
    -SearchBase "CN=Deleted Objects,DC=corp,DC=example,DC=com" | Measure-Object).Count
# B: should list your fine-grained password policies (none, if you have none)
Get-ADFineGrainedPasswordPolicy -Credential $c -Filter * | Select-Object Name
```

The collector's log also says so: it warns when it sees no deleted
objects, and notes when it sees no fine-grained password policy.

### 2.4 Group Policy content (SYSVOL)

The collector also reads the Group Policy files in the domain controller's
SYSVOL and NETLOGON shares (read-only, over SMB). Every domain user can read
them by default, so nothing needs granting, with one exception.

**GPOs with security filtering.** Where *Authenticated Users* was removed
from a GPO's delegation, the account cannot read that GPO at all. The GPO
is then left out of the assessment, and the collector's log counts it as an
unresolved GPO link. To include it:
1. In **Group Policy Management**, open the GPO → **Delegation**.
2. Add the service account with **Read**.

Read does not make the policy apply to the account.

### 2.5 Hardened domains

Some hardening guides remove *Authenticated Users* from the **Pre-Windows
2000 Compatible Access** group. That group is what lets ordinary users read
several user and group attributes the collector checks, such as key
credentials (shadow credentials) and resource-based delegation. Without it,
those attributes read as "not set", and the related checks can miss real
findings.

If you have made that change, give the service account back only what the
group provided:

```
dsacls "DC=corp,DC=example,DC=com" /I:S /G "CORP\svc_adaudit:RP;;user" "CORP\svc_adaudit:RP;;group"
dsacls "CN=AdminSDHolder,CN=System,DC=corp,DC=example,DC=com" /G "CORP\svc_adaudit:RP"
```

The second line covers privileged accounts. Their permissions are copied
from AdminSDHolder within about an hour.

### 2.6 Do not grant

- **Generic Read on the whole domain, as a shortcut.** It can reach the AD
  FS key container, and the collector would rightly report its own
  account as a critical exposure.
- **Read on the KDS root keys** (`CN=Master Root Keys`). That is what a
  "Golden gMSA" attack needs, and the collector checks that ordinary
  accounts cannot read them.
- **LAPS password read**, or any confidential attribute. The collector
  reads only LAPS *expiration times*, which every user can read.

### 2.7 How the collector connects

- **Use LDAPS (TCP 636).** This is the collector's default.
  - **Why:** the collector signs in with a username and password, which
    plain LDAP (389) would send unencrypted. Where the domain controllers
    require LDAP signing (common in hardened domains, and the default for
    new Windows Server 2025 deployments), plain LDAP is refused, and LDAPS
    is the only way in.
  - **What it needs:** the domain controller needs a server-authentication
    certificate (usually issued automatically by an enterprise CA).
  - **Verification:** give the collector your CA certificate, so it
    verifies it is talking to your domain controller (section 5).
- **Which domain controller:** a writable domain controller of the audited
  domain that also hosts AD-integrated DNS. Name it by its fully qualified
  name, for example `dc01.corp.example.com`.
- **Group Policy files:** SMB on TCP 445 to the same domain controller,
  with NTLM. If NTLM is denied there, the collector can use Kerberos
  instead (`sysvol_kerberos = true`, which also needs TCP/UDP 88 and the
  domain controller's fully qualified name).
- **Use the same account for every collection.** Changing the account, or
  its rights, between collections makes objects look changed when they are
  not.

## 3. The Entra ID App Registration (Entra ID collection)

The Entra ID collector signs in as an **App Registration** with a client
secret (OAuth 2.0 client credentials). It uses only **application
permissions** of Microsoft Graph, and every one of them is read-only except
one optional, opt-in permission (see below). It only sends read requests. No
user signs in, and no one is prompted.

Skip this section if you do not want Entra ID collected: the collector then
assesses Active Directory only, and the Entra ID checks are reported as
not assessed.

**Who can do it.** Creating the registration needs at least the
*Application Administrator* role. Granting admin consent to Microsoft
Graph application permissions needs *Privileged Role Administrator* or
*Global Administrator*.

### 3.1 Create the registration (Microsoft Entra admin center)

1. Sign in to <https://entra.microsoft.com>.
2. Go to **Identity → Applications → App registrations → New
   registration**.
   - **Name:** for example `FortifyData AD Audit Collector`.
   - **Supported account types:** *Accounts in this organizational
     directory only (Single tenant)*.
   - **Redirect URI:** leave empty. The app is never used interactively.

   Select **Register**.
3. On the app's **Overview** page, copy the **Application (client) ID** and
   the **Directory (tenant) ID**.
4. Go to **API permissions**.
   1. Remove the `User.Read` *delegated* permission that Entra adds by
      default. The collector does not use it.
   2. Select **Add a permission → Microsoft Graph → Application
      permissions**. Choose *Application permissions*, **not** *Delegated
      permissions*.
   3. Add the five required permissions from section 3.2, and any optional
      ones you want.
5. Still on **API permissions**, select **Grant admin consent for
   \<your tenant\>** and confirm. Each permission must then show:
   - **Type:** `Application`;
   - **Status:** a green *Granted for \<your tenant\>*.
6. Go to **Certificates & secrets → Client secrets → New client secret**.
   - Enter a description and an expiry. We suggest 12 months, with a
     calendar reminder to renew it.
   - Copy the secret's **Value** immediately; it is shown only once. You
     need the *Value*, not the *Secret ID*.
7. Give the three values to the collector (section 5):
   - the tenant ID;
   - the application (client) ID;
   - the client secret value.

**A common mistake: a delegated permission instead of an application
permission.** The Graph permission names exist in both lists. A delegated
grant also shows a green "Granted" mark, but the collector receives
`403 Authorization_RequestDenied` for it. Check that the **Type** column
says `Application` for every permission.

### 3.2 The Microsoft Graph permissions

**Required.** All application permissions, all read-only:

| Permission | What the collector reads with it | Licence needed |
|---|---|---|
| `User.Read.All` | Users, with their link to the on-prem account | – |
| `RoleManagement.Read.Directory` | Directory roles and their holders, role definitions, custom-role assignments, PIM eligible and time-bound assignments | Entra ID P2 for the PIM data |
| `Policy.Read.All` | Security Defaults, Conditional Access, authorization (user consent, guest) policy, authentication methods, cross-tenant access, admin consent requests, app management and federated token validation policies, named locations | Entra ID P1 for Conditional Access |
| `Application.Read.All` | App registrations, service principals, their owners, credentials (expiry dates only) and federated identity credentials | – |
| `Directory.Read.All` | Groups and members, permission grants, domains, licences, directory settings, partner contracts, administrative units, devices | – |

**Optional.** Each one unlocks more checks; grant only those you want.
Without one, or without its licence, the collector records why, and the
checks that need it are reported as *not assessed*: never as a pass.

| Permission | What it unlocks | Licence needed |
|---|---|---|
| `AuditLog.Read.All` | Sign-in activity of users and service principals; MFA registration details | Entra ID P1 |
| `Domain.Read.All` | Federation settings of federated domains (signing certificates, MFA behaviour) | – |
| `RoleManagementPolicy.Read.Directory` | PIM role settings (activation MFA, approval, duration) | Entra ID P2 |
| `Policy.Read.DeviceConfiguration` | Device registration policy | – |
| `OnPremDirectorySynchronization.Read.All` | Directory synchronization settings (password hash sync, soft/hard-match blocking) | – |
| `IdentityRiskyUser.Read.All` | Risky users | Entra ID P2 |
| `IdentityRiskEvent.Read.All` | Risk detections (for example leaked credentials) | Entra ID P2 |
| `OnPremisesPublishingProfiles.ReadWrite.All` | Pass-through authentication agents. **Write-capable; opt-in.** | – |

**About `OnPremisesPublishingProfiles.ReadWrite.All`.** Microsoft offers
no read-only permission for the pass-through authentication agents. The
collector reads them only when this is switched on
(`include_pta_agents = true`), and even then it only reads. The permission
itself, however, would allow changes. Grant it only if that is acceptable
to you; without it, this one source is recorded as skipped.

### 3.3 Alternative: create it with PowerShell

The same registration with the Microsoft Graph PowerShell SDK
(`Install-Module Microsoft.Graph -Scope CurrentUser`), run by a Global
Administrator or Privileged Role Administrator. The script looks up each
permission by name, so no permission IDs are typed by hand.

```powershell
Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All"

$names = @(
    "User.Read.All", "RoleManagement.Read.Directory", "Policy.Read.All",
    "Application.Read.All", "Directory.Read.All"
    # optional, add any of: "AuditLog.Read.All", "Domain.Read.All",
    # "RoleManagementPolicy.Read.Directory", "Policy.Read.DeviceConfiguration",
    # "OnPremDirectorySynchronization.Read.All", "IdentityRiskyUser.Read.All",
    # "IdentityRiskEvent.Read.All"
)

$graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$roles = $graph.AppRoles | Where-Object {
    $_.Value -in $names -and $_.AllowedMemberTypes -contains "Application" }
if ($roles.Count -ne $names.Count) { throw "Some permission names were not found" }

$app = New-MgApplication -DisplayName "FortifyData AD Audit Collector" `
    -SignInAudience AzureADMyOrg `
    -RequiredResourceAccess @{ ResourceAppId = $graph.AppId
        ResourceAccess = @($roles | ForEach-Object { @{ Id = $_.Id; Type = "Role" } }) }
$sp = New-MgServicePrincipal -AppId $app.AppId

# Admin consent: assign each application permission to the app.
foreach ($role in $roles) {
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id `
        -PrincipalId $sp.Id -ResourceId $graph.Id -AppRoleId $role.Id | Out-Null
}

$secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
    DisplayName = "collector"; EndDateTime = (Get-Date).AddMonths(12) }

"Directory (tenant) ID:   $((Get-MgContext).TenantId)"
"Application (client) ID: $($app.AppId)"
"Client secret (shown once): $($secret.SecretText)"
```

Afterwards, check the result in the admin center (**App registrations →
your app → API permissions**): every permission must have Type
`Application` and be granted.

### 3.4 Keeping it working

- **Secret expiry.** When the client secret expires, the Entra ID
  collection fails with an `AADSTS7000222` error.
  - **Effect:** the daemon still evaluates and pushes the Active Directory
    data, and reports the Entra failure in its health report. The Entra ID
    checks are not assessed until the secret is replaced.
  - **Fix:** create a new secret before the old one expires, give it to the
    collector, then delete the old one.
- **Permissions added later.** Admin consent covers only the permissions
  present when it was granted. After adding a permission, select **Grant
  admin consent** again.
- **Conditional Access for workload identities.** If you use it (Entra
  Workload ID licence), allow this app from the address the collector
  connects from.

## 4. Network access

The collector only makes outbound connections; nothing connects to it.

| From the collector to | Port | For |
|---|---|---|
| The domain controller | TCP 636 (LDAPS), or 389 | Active Directory |
| The domain controller | TCP 445 (SMB) | Group Policy files |
| The domain controller | TCP/UDP 88 | Only with `sysvol_kerberos = true` |
| Your DNS servers | 53 | Resolving the domain controller |
| `login.microsoftonline.com`, `graph.microsoft.com` | TCP 443 | Entra ID collection |
| The FortifyData API (`api.fortifydata.com`, or your region's) | TCP 443 | Sending results |

An outbound web proxy is supported for the last two rows. If it inspects
TLS, its CA certificate must be given to the collector.

## 5. Giving the details to the collector

### 5.1 With the collector's own configuration (local mode)

In the installation directory (see `CONTAINER.md`):

| Value | Where |
|---|---|
| Domain controller name | `config/collector.toml`, `[ad] dc_host` |
| Service account name (`svc_adaudit@corp.example.com` or `CORP\svc_adaudit`) | `[ad] username` |
| Service account password | the file `secrets/ad_bind_password` |
| Domain DNS name | `[ad] domain_fqdn` |
| CA certificate (PEM) of the domain controller's LDAPS certificate | a file in `config/`, named in `[ad] ca_cert_file` |
| Entra tenant ID and application (client) ID | `[entra] tenant_id`, `[entra] app_id` |
| Entra client secret | the file `secrets/entra_app_secret` |

Write each secret on the first line of its file, for example:

```
printf '%s\n' 'the password' > secrets/ad_bind_password
```

Then check the configuration with:

```
docker compose run --rm collector --check-config
```

### 5.2 Through the FortifyData portal

When the collector is connected to the FortifyData platform, the same
values are entered in the portal. The collector receives them encrypted to
its own key.

### 5.3 Changing a password or secret

Write the new value to its file, or enter it in the portal. The collector
reads it again before its next run, with no restart. If the previous run
failed because of the old value, the collector notices the change within a
few minutes and runs again.

The collector reports a failed sign-in in its health report:
- AD: `LDAP bind failed`;
- Entra ID: `AADSTS…` errors.

It does not retry a wrong password over and over, so it will not lock the
account out.
