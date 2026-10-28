# Security Policy

## Intended Security Boundary

DeployVault is designed for controlled Windows deployment shares used by trusted deployment operators and authorized WinPE clients. SMB share permissions and NTFS ACLs are the authorization boundary. DeployVault encrypts stored credential payloads and authenticates vault contents, but it does not provide per-credential authorization.

Any principal that can read both the vault and seed files must be treated as authorized to decrypt the entire vault. A credential ID selects an entry; it does not restrict access to that entry. Use separate vault-and-seed pairs when deployment groups require different access.

Credential management operations—including add, update, removal, seed rotation, backup, and restore—are intended to run administratively on the server hosting the deployment share. WinPE deployment identities should receive only the read access required to retrieve credentials during deployment.

## WinPECT Handoff

DeployVault is intended to provide selected credentials in memory to [WinPECT](https://github.com/cmartinezone/WinPECT). WinPECT transfers temporary deployment credentials from Windows PE into the installed operating system using an authenticated encrypted package and separately stored protected bootstrap data. After reboot, WinPECT imports the credential as DPAPI-protected CLIXML for the importing Windows identity and removes temporary transfer artifacts after a successful import.

In the supported workflow, plaintext credentials are not intentionally persisted to unattended files, scripts, command-line arguments, registry values, or the transfer package. This is a persistence guarantee about the software's intended behavior, not a guarantee against process-memory inspection, paging, crash dumps, unsafe downstream commands, or compromise of WinPE or the installed operating system.

## In-Scope Security Properties

- Credentials are not intentionally persisted as plaintext by DeployVault.
- Vault contents are encrypted (`AES-256-CBC`) and authenticated (`HMAC-SHA256`) using keys derived via `PBKDF2-HMAC-SHA256` (`Algorithm = 2`, 100,000 iterations), with backward-compatible reading of `Algorithm = 1` (`PBKDF2-HMAC-SHA1`).
- Incorrect seed material and modified payloads are rejected via constant-time HMAC tag comparison.
- File and directory access is restricted immediately upon initialization, backup, rotation, and restore using locale-independent well-known SIDs (`S-1-5-18`, `S-1-5-32-544`, and `CurrentUser`), and can be further scoped for deployment readers via `SetDeployVaultACL.ps1`.
- Secret reads and mutations are blocked when PowerShell Transcription or Script Block Logging policies (including `WOW6432Node`) or `$global:Transcript` are active, and deserialized entry `.Password` fields are scrubbed in `finally` blocks.

## Out-of-Scope Threats

- A compromised or malicious client authorized to read both files
- Offline decryption after an authorized principal copies both files
- Process-memory inspection, crash dumps, malicious PowerShell hosts, or compromised operating systems
- Credentials explicitly printed, logged, exported, or passed to unsafe downstream tooling
- Security of MDT, MECM, WinPE, Active Directory, SMB, backup infrastructure, or the surrounding network
- Per-ID or per-user authorization within a single vault
- Security defects or misconfiguration in WinPECT; review and validate WinPECT independently as part of the complete deployment system

## Deployment Requirements

1. Restrict both SMB share permissions and NTFS ACLs to approved deployment identities.
2. Treat every vault reader as trusted to retrieve all credentials in that vault.
3. Use least-privilege deployment credentials and separate vaults for separate trust groups.
4. Protect seed, vault, backup, and recovery files as equivalent secret material.
5. Prevent deployment scripts, transcripts, task-sequence logs, and diagnostics from serializing credentials.
6. Rotate affected credentials and seed material after suspected copying or client compromise.
7. Test changes in a non-production deployment share before rollout.
8. Use WinPECT's authenticated transfer workflow for handoff to the installed OS; never replace it with plaintext task-sequence variables or unattended-file values.
9. Stop interactive PowerShell transcripts and disable diagnostic command/output capture before secret operations.
10. Block WinPE readers during seed rotation and restore because the vault and seed cannot be replaced as one atomic filesystem transaction.
11. Verify effective NTFS permissions after every ACL or backup operation; do not treat file creation alone as proof of protection.

## Reporting a Vulnerability

Do not disclose suspected vulnerabilities in a public issue before a fix is available. Use the repository's private GitHub vulnerability-reporting feature or contact the repository owner through a private channel listed on their GitHub profile.

Include the affected version or commit, reproduction steps, security impact, and any suggested mitigation. Do not include real credentials, vault files, seed files, or other sensitive deployment data.

## Security Status

DeployVault has not undergone an independent third-party security audit. The project should not be used as the sole control protecting highly privileged credentials.
