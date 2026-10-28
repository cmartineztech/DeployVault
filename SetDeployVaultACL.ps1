#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory = $true)][string]$VaultDirectory,
    [Parameter(Mandatory = $true)][string[]]$ReadIdentities,
    [string[]]$AdminIdentities = @("S-1-5-32-544", "S-1-5-18")
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

function Resolve-DeployVaultIdentitySid {
    # Resolves a SID string, well-known account alias, or NTAccount name to a locale-independent SecurityIdentifier
    param([Parameter(Mandatory = $true)][object]$Identity)

    if ($Identity -is [System.Security.Principal.SecurityIdentifier]) {
        return $Identity
    }

    $text = ([string]$Identity).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw "Identity reference cannot be empty."
    }

    if ($text -match '^S-\d-\d+-(\d+-)*\d+$') {
        return (New-Object System.Security.Principal.SecurityIdentifier($text))
    }

    if ($text -ieq 'BUILTIN\Administrators' -or $text -ieq 'Administrators') {
        return (New-Object System.Security.Principal.SecurityIdentifier(
            [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,
            $null
        ))
    }

    if ($text -ieq 'NT AUTHORITY\SYSTEM' -or $text -ieq 'SYSTEM') {
        return (New-Object System.Security.Principal.SecurityIdentifier(
            [System.Security.Principal.WellKnownSidType]::LocalSystemSid,
            $null
        ))
    }

    $account = New-Object System.Security.Principal.NTAccount($text)
    return ([System.Security.Principal.SecurityIdentifier]$account.Translate([System.Security.Principal.SecurityIdentifier]))
}

# Require Elevated Administrator Privilege
$principal = [System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "SetDeployVaultACL.ps1 requires an elevated PowerShell Administrator session."
}

# Resolve Path and Verify Files
$resolvedDirectory = (Resolve-Path -LiteralPath $VaultDirectory).Path
$seedFile = Join-Path $resolvedDirectory "localseed.bin"
$vaultFile = Join-Path $resolvedDirectory "localvault.bin"

foreach ($target in @($resolvedDirectory, $seedFile, $vaultFile)) {
    if (-not (Test-Path -LiteralPath $target)) {
        throw "Target path missing: $target"
    }
}

$resolvedAdminSids = @(
    $AdminIdentities |
        ForEach-Object { Resolve-DeployVaultIdentitySid -Identity $_ } |
        Group-Object -Property Value |
        ForEach-Object { $_.Group[0] }
)
$resolvedReaderSids = @(
    $ReadIdentities |
        ForEach-Object { Resolve-DeployVaultIdentitySid -Identity $_ } |
        Group-Object -Property Value |
        ForEach-Object { $_.Group[0] }
)

if (-not $PSCmdlet.ShouldProcess($resolvedDirectory, "replace inherited ACLs on the vault directory and files")) {
    return
}

$dirInherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$dirPropagate = [System.Security.AccessControl.PropagationFlags]::None
$allowType = [System.Security.AccessControl.AccessControlType]::Allow
$fullRights = [System.Security.AccessControl.FileSystemRights]::FullControl
$dirReadRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::Synchronize
$fileReadRights = [System.Security.AccessControl.FileSystemRights]::Read -bor [System.Security.AccessControl.FileSystemRights]::Synchronize

# Apply Directory ACLs
$dirSec = New-Object System.Security.AccessControl.DirectorySecurity
$dirSec.SetAccessRuleProtection($true, $false) # Break inheritance

foreach ($adminSid in $resolvedAdminSids) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $adminSid, $fullRights, $dirInherit, $dirPropagate, $allowType
    )
    $dirSec.AddAccessRule($rule)
}

foreach ($readerSid in $resolvedReaderSids) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $readerSid, $dirReadRights, $dirInherit, $dirPropagate, $allowType
    )
    $dirSec.AddAccessRule($rule)
}

Set-Acl -LiteralPath $resolvedDirectory -AclObject $dirSec

# Apply Explicit File ACLs (Seed & Vault)
foreach ($file in @($seedFile, $vaultFile)) {
    $fileSec = New-Object System.Security.AccessControl.FileSecurity
    $fileSec.SetAccessRuleProtection($true, $false)

    foreach ($adminSid in $resolvedAdminSids) {
        $fileSec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $adminSid, $fullRights, $allowType
        )))
    }
    foreach ($readerSid in $resolvedReaderSids) {
        $fileSec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $readerSid, $fileReadRights, $allowType
        )))
    }
    Set-Acl -LiteralPath $file -AclObject $fileSec
}

# Maintain Hidden + System Seed File Attributes
$seedItem = Get-Item -LiteralPath $seedFile -Force
$seedItem.Attributes = $seedItem.Attributes `
    -bor [System.IO.FileAttributes]::Hidden `
    -bor [System.IO.FileAttributes]::System

Write-Host "SUCCESS: DeployVault ACLs successfully applied to directory and files." -ForegroundColor Green
Write-Host "  - Administrators (Full Control): $(($resolvedAdminSids | ForEach-Object { $_.Value }) -join ', ')" -ForegroundColor Gray
Write-Host "  - Deployment Readers (Read-Only): $(($resolvedReaderSids | ForEach-Object { $_.Value }) -join ', ')" -ForegroundColor Gray
