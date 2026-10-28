# DeployVault

**DeployVault** is a security-focused local credential vault engine written in PowerShell. It is designed to replace plaintext credentials in answer files (`Unattend.xml`, `.ini`, `.txt`, `.json`) and scripts used by automated deployment environments such as MDT, SCCM/MECM, task sequences, and WinPE.

DeployVault provides authenticated encryption, crash-resilient writes, NTFS ACL integration, and credential lifecycle management. It has not undergone an independent security audit and should be deployed as one control within a secured deployment environment.

---

## Security Model and Trust Boundary

DeployVault is intended for a controlled deployment share where authorized WinPE clients and deployment operators can read both the encrypted vault and its companion seed file. Access to the deployment share is the primary authorization boundary.

The following limitations are intentional and must be understood before deployment:

- A credential ID is a lookup selector, not a per-credential authorization boundary.
- Any identity or device that can read both `localvault.bin` and `localseed.bin` can copy the pair and decrypt every enabled credential offline.
- DeployVault does not protect credentials from a compromised or malicious authorized WinPE client.
- Encryption protects against plaintext exposure, accidental inspection, and undetected vault modification. It does not replace SMB permissions, NTFS ACLs, network isolation, or deployment-account governance.
- Passwords are not intentionally written to plaintext files. During a credential operation, plaintext temporarily exists in process memory as managed PowerShell/.NET objects and may be exposed by process dumps, a compromised host, or unsafe diagnostic tooling.

Use DeployVault only when every principal granted access to both files is trusted to retrieve all credentials stored in that vault. Use separate vault-and-seed pairs when different deployment groups require different credential access.

### WinPECT Integration

DeployVault is designed to work with [WinPECT](https://github.com/cmartinezone/WinPECT) as part of an end-to-end deployment credential flow:

```text
Deployment-share server             Windows PE                     Installed Windows
-----------------------             ----------                     -----------------
Administrators manage vault         Read credential by ID          Verify transfer
and seed material                    into process memory             Import as DPAPI-protected
                                      |                              PSCredential CLIXML
                                      v                              files
                                    WinPECT creates an      reboot
                                    authenticated encrypted ------>
                                    transfer package and
                                    separate bootstrap data
```

- Credential add, update, removal, seed rotation, backup, and restore operations are administrative tasks performed on the server hosting the deployment share.
- Authorized WinPE deployment identities receive read-only access, and the deployment workflow requests the credential IDs it requires. This is workflow selection, not technical enforcement against other IDs in the same vault.
- The retrieved `PSCredential` is passed to WinPECT in memory. DeployVault and WinPECT do not intentionally write the plaintext username/password pair to an unattended file, script, command line, registry value, or transfer package.
- WinPECT stores an authenticated encrypted package on the target volume and separate protected bootstrap data in the offline Windows `SOFTWARE` registry hive.
- After Windows starts, WinPECT verifies and decrypts the transfer and exports DPAPI-protected `PSCredential` CLIXML for the importing Windows identity. Successful import removes the temporary package and bootstrap registry data.

This workflow prevents intentional plaintext persistence during transfer. It does not protect credentials from a compromised WinPE environment, a compromised importing process, memory inspection, or a principal that can copy both the DeployVault vault and seed files.

---

## Technical Architecture & Security Controls

DeployVault uses standard cryptographic primitives with operational safeguards appropriate to its documented trust boundary:

### 1. Authenticated Encryption (Encrypt-then-MAC)
- **Encryption Algorithm:** AES-256-CBC with a cryptographically secure 16-byte initialization vector (IV) generated per write.
- **Message Authentication Tag:** HMAC-SHA256 computed over the binary header (which contains the IV) and ciphertext (`Encrypt-then-MAC`).
- **Protection Scope:** Detects payload tampering and prevents unauthenticated ciphertext modification. Confidentiality depends on keeping the vault-and-seed pair inside the trusted deployment boundary.

### 2. Key Derivation & Memory Hygiene
- **Key Derivation Function:** PBKDF2-HMAC-SHA256 (`Algorithm = 2`, 100,000 iterations over a 32-byte cryptographically random salt, with a deterministic pure-.NET `HMACSHA256` fallback when the 4-argument `Rfc2898DeriveBytes` constructor is unavailable on older .NET builds). Legacy `Algorithm = 1` (`PBKDF2-HMAC-SHA1`) vaults remain readable for backward compatibility and are transparently upgraded to `Algorithm = 2` on the next write.
- **Single-Derivation Lock Reuse:** Within a locked mutation (`Set-VaultCredential`, `Remove-VaultCredential`, `Write-VaultEntries`), the derived 64-byte master key is passed across internal read, encrypt, and pre-commit verification steps so PBKDF2 runs once per operation.
- **Key Separation:** Generates 64 derived bytes total: 32 bytes for the AES-256 encryption key and 32 bytes for the HMAC-SHA256 authentication tag.
- **Memory Hygiene:** Sensitive byte arrays are explicitly cleared via `[Array]::Clear()`, and deserialized entry `.Password` properties are scrubbed via `Clear-VaultEntriesMemory` in `finally` blocks across all CRUD and lifecycle cmdlets.

### 3. Authentication-Tag Comparison
- **Fixed-Work Comparison:** `Test-VaultFixedTimeEqual` compares every byte when the tag lengths match, avoiding an early exit based on the first differing byte. The implementation has not undergone dedicated side-channel analysis.

### 4. Crash Resilience & Pre-Commit Verification
- **Pre-Commit Verification:** All write operations build and encrypt a candidate payload into a temporary file (`.tmp`), apply restrictive NTFS ACLs using locale-independent SIDs (`CurrentUser`, `S-1-5-18`, `S-1-5-32-544`), and re-read/decrypt the temporary file in memory before touching the live vault.
- **Single-File Replacement & Mid-Swap Read Retry:** Normal vault-content updates use `[System.IO.File]::Replace` to replace the live vault file and retain a backup. `Read-VaultEnvelope` includes a 1-retry (150ms) backoff to tolerate transient mid-swap reads between `localseed.bin` and `localvault.bin`.

### 5. Multi-Process Concurrency Locking
- **Exclusive Mutation Lock:** Credential mutations and lifecycle operations acquire an exclusive filesystem lock (`localvault.bin.lock`) with timeout retry behavior. Credential reads are lock-free; prevent WinPE reads during seed rotation or restore.

### 6. Logging Safety & Locale-Independent ACLs
- **Policy Check:** `Assert-VaultSafeLogging` blocks secret reads and mutations when Windows PowerShell transcription or script block logging is enabled through `HKLM` or `HKCU` policy paths (including `WOW6432Node`) or when `$global:Transcript` is set.
- **Locale-Independent SIDs:** `Initialize-Vault`, `Protect-VaultDirectoryAcl`, `Protect-VaultFileAcl`, and `SetDeployVaultACL.ps1` use well-known SIDs (`S-1-5-18` Local SYSTEM and `S-1-5-32-544` Builtin Administrators) rather than localized account names so ACL lockdown works on non-English Windows installations.
- **Operator Requirement:** An interactively started transcript is not reliably detectable through supported Windows PowerShell 5.1 APIs. Stop all transcripts and disable diagnostic command/output capture before retrieving or updating credentials.

---

## Core Repository Structure

| File | Description |
| :--- | :--- |
| [DeployVault.ps1](DeployVault.ps1) | Core credential engine containing cryptographic functions, CRUD commands, and lifecycle routines. |
| [Init.ps1](Init.ps1) | Interactive deployment helper to initialize new vault/seed pairs and prompt for initial credentials. |
| [SetDeployVaultACL.ps1](SetDeployVaultACL.ps1) | Elevated administrative script to break permission inheritance and enforce strict NTFS ACLs for Active Directory deployment groups. |
| [TestDeployVault.ps1](TestDeployVault.ps1) | Automated 8-stage verification test suite covering initialization, encryption, backups, restores, rotation, tamper detection, and concurrency. |
| [README.md](README.md) | Official documentation and reference guide. |
| [SECURITY.md](SECURITY.md) | Security boundary, deployment requirements, limitations, and vulnerability-reporting policy. |
| [LICENSE](LICENSE) | MIT license governing use and distribution. |

---

## Supported Environment

- Windows PowerShell 5.1
- Windows or Windows PE with the PowerShell, .NET, scripting, and WMI optional components required by the surrounding deployment workflow
- NTFS storage for live vault, seed, backup, and recovery files
- A controlled SMB deployment share when the vault is accessed remotely

PowerShell 7 may work for some operations but is not the primary compatibility target. Validate the complete DeployVault and WinPECT workflow on every supported Windows PE image and Windows build before production rollout.

---

## Quick Start Guide

### 1. Dot-Source the Engine
Dot-source the engine script inside your task sequence or deployment script:

```powershell
. .\DeployVault.ps1
```

### 2. Initialize a New Vault
Initialize a new master seed (`localseed.bin`) and vault binary (`localvault.bin`). The seed file is automatically assigned **Hidden** and **System** filesystem attributes:

```powershell
Initialize-Vault `
    -VaultPath .\Vault\localvault.bin `
    -SeedPath .\Vault\localseed.bin
```

### 3. Restrict Directory & File ACL Permissions
Run `SetDeployVaultACL.ps1` from an **elevated Administrator PowerShell session** to grant Read access only to specified Active Directory deployment accounts while giving Full Control to Administrators and SYSTEM:

```powershell
.\SetDeployVaultACL.ps1 `
    -VaultDirectory .\Vault `
    -ReadIdentities "CONTOSO\DeploymentReaders", "CONTOSO\Domain Admins"
```

> **Trust warning:** Every identity in `ReadIdentities` can read both the seed and vault and must therefore be trusted to decrypt every credential in that vault. Do not use this list as a per-credential access-control mechanism.

### 4. Save a Credential
Add or update a credential in the vault using a `SecureString` password input:

```powershell
$secPassword = Read-Host "Enter Password" -AsSecureString

Set-VaultCredential `
    -VaultPath .\Vault\localvault.bin `
    -SeedPath .\Vault\localseed.bin `
    -CredentialId "DomainJoin" `
    -Username "CONTOSO\svc-domainjoin" `
    -Password $secPassword `
    -Description "MDT Automated Domain Join Account"
```

### 5. Retrieve a Credential
Retrieve credentials directly as a standard `PSCredential` object for use with standard cmdlets (`New-PSDrive`, `Invoke-Command`, `Join-Domain`):

```powershell
$cred = Get-VaultCredential `
    -VaultPath .\Vault\localvault.bin `
    -SeedPath .\Vault\localseed.bin `
    -CredentialId "DomainJoin"

Write-Host "Loaded credential for identity: $($cred.UserName)"

# Memory cleanup: Clear variable after execution
$cred = $null
```

### 6. View Vault Metadata Summary
View non-secret metadata (passwords are strictly excluded from summary output):

```powershell
Get-VaultSummary `
    -VaultPath .\Vault\localvault.bin `
    -SeedPath .\Vault\localseed.bin | Format-Table -AutoSize
```

### 7. Remove a Credential
Delete an entry from the vault by its ID:

```powershell
Remove-VaultCredential `
    -VaultPath .\Vault\localvault.bin `
    -SeedPath .\Vault\localseed.bin `
    -CredentialId "DomainJoin"
```

---

## Common Credential Examples

DeployVault stores credentials as a username plus a protected password/secret value. It does not currently expose a separate arbitrary-secret object type.

### Local Administrator Credential

Use a deployment-specific local Administrator credential only when the deployment workflow requires one. Prefer a unique password per device and use Windows LAPS to manage the account after the installed operating system is enrolled.

```powershell
$localAdminPassword = Read-Host "Enter the temporary local Administrator password" -AsSecureString

try {
    Set-VaultCredential `
        -VaultPath .\Vault\localvault.bin `
        -SeedPath .\Vault\localseed.bin `
        -CredentialId "LocalAdministrator" `
        -Username ".\Administrator" `
        -Password $localAdminPassword `
        -Description "Temporary deployment-time local Administrator"
}
finally {
    $localAdminPassword.Dispose()
}
```

Retrieve it in WinPE as a `PSCredential` for the deployment step or WinPECT handoff:

```powershell
$localAdminCredential = Get-VaultCredential `
    -VaultPath .\Vault\localvault.bin `
    -SeedPath .\Vault\localseed.bin `
    -CredentialId "LocalAdministrator"

# Pass $localAdminCredential directly to the deployment operation or WinPECT.
# Do not print or serialize the credential.
```

### API Client Secret or API Key

For an API client credential, store the client ID or service identity in `Username` and the client secret or API key in `Password`:

```powershell
$apiSecret = Read-Host "Enter the deployment API secret" -AsSecureString

try {
    Set-VaultCredential `
        -VaultPath .\Vault\localvault.bin `
        -SeedPath .\Vault\localseed.bin `
        -CredentialId "DeploymentApi" `
        -Username "deployment-client" `
        -Password $apiSecret `
        -Description "Deployment service API credential"
}
finally {
    $apiSecret.Dispose()
}
```

Retrieve the pair as a `PSCredential` and pass it directly to an SDK or helper that accepts `PSCredential` or `SecureString`:

```powershell
$apiCredential = Get-VaultCredential `
    -VaultPath .\Vault\localvault.bin `
    -SeedPath .\Vault\localseed.bin `
    -CredentialId "DeploymentApi"

$clientId = $apiCredential.UserName
$secret = $apiCredential.Password

# Prefer an API client that accepts SecureString or PSCredential directly.
# Converting $secret to a normal string creates managed plaintext in memory.
```

For a key with no natural username, use a non-secret descriptor such as `api-key` in `Username`. Never place an API key in `CredentialId`, `Username`, `Description`, a command line, or diagnostic output.

---

## Lifecycle Operations

### Master Seed Rotation
Re-key the vault with a new master seed while retaining saved credentials. Rotation executes under an exclusive mutation lock, applies restrictive ACLs to `.rotation.bak` recovery files, and supports `-RemoveRecoveryFiles` to purge recovery artifacts automatically after verification:

```powershell
Invoke-VaultSeedRotation `
    -VaultPath .\Vault\localvault.bin `
    -SeedPath .\Vault\localseed.bin `
    -RemoveRecoveryFiles
```

Schedule rotation during a maintenance window with no active WinPE readers. The seed and vault files are replaced sequentially, so an unlocked reader could otherwise observe a mismatched pair. Protect and remove recovery files according to your recovery and retention policy after validating the rotated vault.

### Creating Vault Backups
Create timestamped, ACL-protected backup pairs (`vault-YYYYMMDDTHHMMSSfffZ.bin` and `seed-YYYYMMDDTHHMMSSfffZ.bin`) with configurable retention purging:

```powershell
Backup-Vault `
    -VaultPath .\Vault\localvault.bin `
    -SeedPath .\Vault\localseed.bin `
    -BackupDirectory .\Vault\Backups `
    -RetentionCount 10
```

After backup creation, verify the effective NTFS ACLs and confirm that only the intended administrative identities can read the backup directory. Treat any ACL error as a failed backup-security operation.

### Restoring a Backup
Restore a decryptable backup pair after validating its envelope schema. `Restore-Vault` verifies the installed result against the selected candidate pair, applies restrictive ACLs to `.pre-restore` recovery files, and supports `-RemoveRecoveryFiles` to purge them after post-swap validation:

```powershell
Restore-Vault `
    -VaultPath .\Vault\localvault.bin `
    -SeedPath .\Vault\localseed.bin `
    -VaultBackup .\Vault\Backups\vault-20260802T100000000Z.bin `
    -SeedBackup .\Vault\Backups\seed-20260802T100000000Z.bin `
    -RemoveRecoveryFiles
```

Perform restores during a maintenance window with no active WinPE readers. Keep the generated pre-restore recovery files until the restored vault has been validated, then protect or remove them according to policy.

---

## Current Operational Limitations

- Any reader that can copy both the vault and seed can decrypt the complete vault offline.
- Interactive `Start-Transcript` sessions are not reliably detected; operators must stop them before secret operations.
- Normal vault-file writes use atomic replacement, but seed rotation and restore cannot atomically replace both files as one filesystem transaction.
- Reads do not acquire the mutation lock. Block deployment access during seed rotation and restore.
- ACL application must be independently verified. A successful file copy alone does not prove the destination permissions are correct.
- DeployVault has not undergone an independent cryptographic or security audit.

---

## Automated Verification & Testing

Run the built-in 8-stage automated test suite before deploying new vault configurations to production environments:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\TestDeployVault.ps1
```

The test suite validates:
1. Vault initialization & hidden file attributes
2. Credential round-trip operations & schema metadata envelope tracking
3. Timestamped backup creation
4. Authentication-tag tamper rejection
5. Backup restoration capabilities
6. Seed rotation, recovery-file creation, and credential continuity
7. Concurrency lock contention
8. Credential deletion cleanups

The suite does not currently prove effective ACL configuration, resistance to memory inspection, transcript detection, two-file crash atomicity, or cryptographic side-channel properties. Validate those controls operationally in the target deployment environment.

---

## Security Best Practices

1. **Secure the Share First:** Require SMB 3 encryption where supported, disable guest access, restrict share permissions, and limit the deployment network to approved clients.
2. **NTFS ACL Lockdown:** Enforce strict ACLs using `SetDeployVaultACL.ps1`. Never grant Write or Full Control access to standard users or automated reader accounts.
3. **Treat Readers as Vault Administrators:** A reader of both files can decrypt the entire vault. Create separate vaults for groups that must not share credential access.
4. **Use Least-Privilege Credentials:** Store deployment-specific accounts with the minimum required permissions. Avoid domain-administrator and other broadly privileged credentials.
5. **Prevent Log Serialization:** Do not log `$cred`, call `$cred.GetNetworkCredential().Password` in diagnostic output, or echo plaintext secrets to console, transcript, or task-sequence logs.
6. **Harden WinPE:** Treat boot images, prestart commands, task-sequence variables, and command shells as part of the trusted boundary. Remove debugging tools and interactive access where operationally possible.
7. **Rotate After Exposure:** Rotate the stored credential and the vault seed if an authorized client, deployment account, seed, vault, or backup pair may have been copied or compromised.
8. **Protect Backups as Live Secrets:** Store vault and seed backups together only in access-controlled locations protected to the same standard as the live deployment share.
9. **Avoid Persistent Copies:** Do not copy the seed, vault, recovery files, or decrypted credentials to local disks, logs, package caches, or general-purpose file shares.
10. **Clear References After Use:** Dispose `SecureString` objects where possible and clear credential variables promptly. Garbage collection is not a guarantee that managed plaintext has been physically erased.
11. **Use WinPECT for OS Handoff:** Transfer selected credentials into the installed operating system through WinPECT's authenticated package and protected bootstrap workflow. Do not substitute plaintext task-sequence variables, unattended-file values, or command-line arguments.
12. **Use Maintenance Windows:** Prevent WinPE vault access while rotating the seed or restoring a backup, then validate the live pair before resuming deployments.

For vulnerability reporting and the supported security scope, see [SECURITY.md](SECURITY.md).

---

## License and Disclaimer

DeployVault is available under the [MIT License](LICENSE).

The software is provided **as is**, without warranty of any kind. Its security controls reduce risk but cannot guarantee that credentials will never be exposed. Validate DeployVault and its surrounding deployment workflow against your own Windows PE images, Windows versions, infrastructure, and threat model before production use.
