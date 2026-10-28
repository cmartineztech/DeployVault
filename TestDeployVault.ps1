#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# Dot-source DeployVault Core Engine
. (Join-Path $PSScriptRoot "DeployVault.ps1")

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("DeployVault-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$vault = Join-Path $testRoot "localvault.bin"
$seed = Join-Path $testRoot "localseed.bin"
$backupDirectory = Join-Path $testRoot "backup"
$password = $null

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

try {
    Write-Host "[1/10] Testing Initialization, Hidden Attributes & Initial NTFS ACLs..." -ForegroundColor Cyan
    Initialize-Vault -VaultPath $vault -SeedPath $seed
    $seedAttributes = (Get-Item -LiteralPath $seed -Force).Attributes
    Assert-True (($seedAttributes -band [System.IO.FileAttributes]::Hidden) -ne 0) "seed is hidden"
    Assert-True (($seedAttributes -band [System.IO.FileAttributes]::System) -ne 0) "seed is a system file"
    Assert-True (@(Get-VaultSummary -VaultPath $vault -SeedPath $seed).Count -eq 0) "new vault is empty"

    $dirAcl = Get-Acl -LiteralPath $testRoot
    $vaultAcl = Get-Acl -LiteralPath $vault
    $seedAcl = Get-Acl -LiteralPath $seed
    Assert-True $dirAcl.AreAccessRulesProtected "vault parent directory disables ACL inheritance"
    Assert-True $vaultAcl.AreAccessRulesProtected "vault binary disables ACL inheritance"
    Assert-True $seedAcl.AreAccessRulesProtected "seed binary disables ACL inheritance"

    $resolvedAdminSid = Resolve-VaultIdentitySid -Identity "BUILTIN\Administrators"
    $resolvedSystemSid = Resolve-VaultIdentitySid -Identity "NT AUTHORITY\SYSTEM"
    Assert-True ($resolvedAdminSid.Value -eq "S-1-5-32-544") "Administrators resolves to S-1-5-32-544"
    Assert-True ($resolvedSystemSid.Value -eq "S-1-5-18") "SYSTEM resolves to S-1-5-18"

    [byte[]]$initialVaultBytes = [System.IO.File]::ReadAllBytes($vault)
    Assert-True ($initialVaultBytes[5] -eq 2) "new vault defaults to Algorithm 2 (PBKDF2-HMAC-SHA256)"
    Clear-VaultBytes $initialVaultBytes

    Write-Host "[2/10] Testing PBKDF2-HMAC-SHA256 Fallback & Algorithm 1 Backward Compatibility..." -ForegroundColor Cyan
    [byte[]]$rawSeed = [System.IO.File]::ReadAllBytes($seed)
    try {
        [byte[]]$fallbackKey = Invoke-VaultPbkdf2Sha256 -Password $rawSeed[32..63] -Salt $rawSeed[0..31] -Iterations 100000 -ByteCount 64
        [byte[]]$engineKey = Get-VaultMasterBytes -SeedPath $seed -Algorithm 2
        Assert-True (Test-VaultFixedTimeEqual $fallbackKey $engineKey) "pure-.NET PBKDF2-SHA256 matches engine Algorithm 2 key derivation"
        Clear-VaultBytes $fallbackKey
        Clear-VaultBytes $engineKey
    }
    finally {
        Clear-VaultBytes $rawSeed
    }

    # Verify legacy Algorithm 1 payload can be read and transparently upgraded
    [byte[]]$legacyMaster = Get-VaultMasterBytes -SeedPath $seed -Algorithm 1
    try {
        $legacyEntry = [pscustomobject][ordered]@{
            Id = "LegacyCred"; Username = "CONTOSO\legacy"; Password = "LegacyPassword123!"; Description = "V1 KDF"; Enabled = $true; CreatedUtc = [DateTime]::UtcNow.ToString("o"); LastUpdatedUtc = [DateTime]::UtcNow.ToString("o")
        }
        [byte[]]$legacyPayload = ConvertTo-VaultPayload -Entries @($legacyEntry) -MasterBytes $legacyMaster -Algorithm 1
        Assert-True ($legacyPayload[5] -eq 1) "legacy payload header marks Algorithm 1"
        [System.IO.File]::WriteAllBytes($vault, $legacyPayload)
        Clear-VaultBytes $legacyPayload

        $legacyCred = Get-VaultCredential -VaultPath $vault -SeedPath $seed -CredentialId "LegacyCred"
        Assert-True ($legacyCred.UserName -eq "CONTOSO\legacy") "legacy Algorithm 1 vault entry reads cleanly"
        Remove-VaultCredential -VaultPath $vault -SeedPath $seed -CredentialId "LegacyCred"
        [byte[]]$upgradedBytes = [System.IO.File]::ReadAllBytes($vault)
        Assert-True ($upgradedBytes[5] -eq 2) "writing to legacy vault upgrades header to Algorithm 2"
        Clear-VaultBytes $upgradedBytes
    }
    finally {
        Clear-VaultBytes $legacyMaster
    }

    Write-Host "[3/10] Testing Credential Round-Trip & Envelope Tracking..." -ForegroundColor Cyan
    $password = ConvertTo-SecureString "SuperSecretPassword!" -AsPlainText -Force
    Set-VaultCredential -VaultPath $vault -SeedPath $seed -CredentialId "DeploymentAcc" `
        -Username "CONTOSO\deployer" -Password $password -Description "Deployment account test"
    
    $credential = Get-VaultCredential -VaultPath $vault -SeedPath $seed -CredentialId "DeploymentAcc"
    Assert-True ($credential.UserName -eq "CONTOSO\deployer") "credential username matches"
    Assert-True ($credential.GetNetworkCredential().Password -eq "SuperSecretPassword!") "credential password matches"

    $summary = @(Get-VaultSummary -VaultPath $vault -SeedPath $seed)
    Assert-True ($summary.Count -eq 1) "summary returns 1 item"
    Assert-True (-not ($summary[0].PSObject.Properties.Name -contains "Password")) "summary excludes password payload"

    $metadataBefore = Read-VaultEnvelope -VaultPath $vault -SeedPath $seed
    Assert-True ($metadataBefore.SchemaVersion -eq 3) "envelope schema version is valid"
    Clear-VaultEntriesMemory -Entries @($metadataBefore.Entries)
    Assert-True ($null -eq $metadataBefore.Entries[0].Password) "Clear-VaultEntriesMemory scrubs entry Password property"

    Set-VaultCredential -VaultPath $vault -SeedPath $seed -CredentialId "DeploymentAcc" `
        -Username "CONTOSO\deployer" -Password $password -Description "Updated test credential"
    $metadataAfter = Read-VaultEnvelope -VaultPath $vault -SeedPath $seed
    try {
        Assert-True ($metadataBefore.VaultId -eq $metadataAfter.VaultId) "vault ID is stable"
        Assert-True ([long]$metadataAfter.Generation -gt [long]$metadataBefore.Generation) "generation counter increases"
    }
    finally {
        Clear-VaultEntriesMemory -Entries @($metadataAfter.Entries)
    }

    Write-Host "[4/10] Testing Transcription & Logging Gate..." -ForegroundColor Cyan
    $global:Transcript = "C:\Temp\active-transcript.txt"
    try {
        $transcriptBlocked = $false
        try { Read-VaultEnvelope -VaultPath $vault -SeedPath $seed | Out-Null }
        catch { $transcriptBlocked = $true }
        Assert-True $transcriptBlocked "Read-VaultEnvelope blocks when global Transcript indicator is set"
    }
    finally {
        Remove-Variable -Name Transcript -Scope Global -ErrorAction SilentlyContinue
    }

    Write-Host "[5/10] Testing Backup Functionality & ACL Protection..." -ForegroundColor Cyan
    $backup = Backup-Vault -VaultPath $vault -SeedPath $seed -BackupDirectory $backupDirectory
    Assert-True (Test-Path -LiteralPath $backup.VaultBackup) "vault backup created"
    Assert-True (Test-Path -LiteralPath $backup.SeedBackup) "seed backup created"
    Assert-True (Get-Acl -LiteralPath $backupDirectory).AreAccessRulesProtected "backup directory ACL inheritance disabled"
    Assert-True (Get-Acl -LiteralPath $backup.VaultBackup).AreAccessRulesProtected "vault backup file ACL inheritance disabled"
    Assert-True (Get-Acl -LiteralPath $backup.SeedBackup).AreAccessRulesProtected "seed backup file ACL inheritance disabled"

    Write-Host "[6/10] Testing Tamper Detection (Constant-Time HMAC)..." -ForegroundColor Cyan
    [byte[]]$tampered = [System.IO.File]::ReadAllBytes($vault)
    $tampered[$tampered.Length - 1] = $tampered[$tampered.Length - 1] -bxor 1
    [System.IO.File]::WriteAllBytes($vault, $tampered)
    Clear-VaultBytes $tampered

    $tamperRejected = $false
    try { Read-VaultEntries -VaultPath $vault -SeedPath $seed | Out-Null }
    catch { $tamperRejected = $true }
    Assert-True $tamperRejected "tampered payload was rejected"

    Write-Host "[7/10] Testing Restore Capabilities & Recovery Cleanup..." -ForegroundColor Cyan
    $restoreResult = Restore-Vault -VaultPath $vault -SeedPath $seed `
        -VaultBackup $backup.VaultBackup -SeedBackup $backup.SeedBackup -RemoveRecoveryFiles -Confirm:$false
    Assert-True ((Get-VaultCredential -VaultPath $vault -SeedPath $seed -CredentialId "DeploymentAcc").UserName -eq "CONTOSO\deployer") "restore succeeded"
    Assert-True ([bool]$restoreResult.RecoveryRemoved) "Restore-Vault -RemoveRecoveryFiles purged pre-restore files"

    Write-Host "[8/10] Testing Seed Rotation & Recovery File Hygiene..." -ForegroundColor Cyan
    $oldSeedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $seed).Hash
    $rotation = Invoke-VaultSeedRotation -VaultPath $vault -SeedPath $seed -Confirm:$false
    $newSeedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $seed).Hash
    Assert-True ($oldSeedHash -ne $newSeedHash) "seed rotation changed seed binary"
    Assert-True (Test-Path -LiteralPath $rotation.SeedRecovery) "rotation seed recovery exists"
    Assert-True (Test-Path -LiteralPath $rotation.VaultRecovery) "rotation vault recovery exists"
    Assert-True (Get-Acl -LiteralPath $rotation.SeedRecovery).AreAccessRulesProtected "rotation seed recovery has protected ACL"
    Assert-True (Get-Acl -LiteralPath $rotation.VaultRecovery).AreAccessRulesProtected "rotation vault recovery has protected ACL"
    Assert-True ((Get-VaultCredential -VaultPath $vault -SeedPath $seed -CredentialId "DeploymentAcc").UserName -eq "CONTOSO\deployer") "credentials survive rotation"

    $rotationPurged = Invoke-VaultSeedRotation -VaultPath $vault -SeedPath $seed -RemoveRecoveryFiles -Confirm:$false
    Assert-True ([bool]$rotationPurged.RecoveryRemoved) "Invoke-VaultSeedRotation -RemoveRecoveryFiles purges recovery artifacts"
    Assert-True (-not (Test-Path -LiteralPath "$seed.rotation.bak")) "seed.rotation.bak removed when requested"
    Assert-True (-not (Test-Path -LiteralPath "$vault.rotation.bak")) "vault.rotation.bak removed when requested"

    Write-Host "[9/10] Testing Concurrency Lock Contention..." -ForegroundColor Cyan
    $heldLock = Open-VaultLock -VaultPath $vault
    try {
        $lockRejected = $false
        try { Open-VaultLock -VaultPath $vault -TimeoutSeconds 1 | Out-Null }
        catch { $lockRejected = $true }
        Assert-True $lockRejected "competing caller blocked by process lock"
    }
    finally {
        $heldLock.Dispose()
    }

    Write-Host "[10/10] Testing Credential Deletion..." -ForegroundColor Cyan
    Remove-VaultCredential -VaultPath $vault -SeedPath $seed -CredentialId "DeploymentAcc"
    $remaining = @(Get-VaultSummary -VaultPath $vault -SeedPath $seed | Where-Object { $_.Id -eq "DeploymentAcc" })
    Assert-True ($remaining.Count -eq 0) "credential successfully removed"

    Write-Host "`nSUCCESS: All DeployVault automated test cases passed cleanly!" -ForegroundColor Green
}
finally {
    if ($null -ne $password) { $password.Dispose() }
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
