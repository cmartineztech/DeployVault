#requires -Version 5.1
Set-StrictMode -Version 2.0

# ==============================================================================
# Script: DeployVault.ps1
# Description: Production-grade credential vault engine using AES-256-CBC,
#              HMAC-SHA256, PBKDF2-HMAC-SHA256, atomic file swaps, process
#              locks, locale-independent SID ACLs, and memory hygiene.
# Binary Magic Tag: VLT3 (0x56, 0x4C, 0x54, 0x33)
# ==============================================================================

# Script Constants
$script:VaultMagic = [byte[]](0x56, 0x4C, 0x54, 0x33)
$script:VaultVersion = 3
$script:VaultDefaultAlgorithm = 2 # 1 = PBKDF2-HMAC-SHA1 (legacy), 2 = PBKDF2-HMAC-SHA256
$script:VaultHeaderLength = 24    # Magic(4), Version(1), Algorithm(1), Reserved(2), IV(16)
$script:VaultTagLength = 32       # HMAC-SHA256 tag length
$script:VaultMaxBytes = 10MB      # Payload safety cap

# ==============================================================================
# SECTION 1: CRYPTOGRAPHIC CORE & MEMORY HYGIENE
# ==============================================================================

function Clear-VaultBytes {
    # Overwrites sensitive byte arrays in memory with zeroes
    param([AllowNull()][byte[]]$Bytes)
    if ($null -ne $Bytes) { [Array]::Clear($Bytes, 0, $Bytes.Length) }
}

function Clear-VaultEntriesMemory {
    # Scrubs plaintext Password properties from deserialized entry objects in memory
    param([AllowNull()][AllowEmptyCollection()][array]$Entries)
    if ($null -eq $Entries) { return }
    foreach ($entry in $Entries) {
        if ($null -ne $entry -and $null -ne $entry.PSObject.Properties['Password']) {
            $entry.Password = $null
        }
    }
}

function Test-VaultFixedTimeEqual {
    # Performs constant-time byte comparison to prevent HMAC timing side-channel attacks
    param([byte[]]$Left, [byte[]]$Right)
    if ($null -eq $Left -or $null -eq $Right -or $Left.Length -ne $Right.Length) { return $false }
    [int]$difference = 0
    for ($i = 0; $i -lt $Left.Length; $i++) {
        $difference = $difference -bor ($Left[$i] -bxor $Right[$i])
    }
    return ($difference -eq 0)
}

function Invoke-VaultPbkdf2Sha256 {
    # Deterministic pure-.NET RFC 2898 PBKDF2-HMAC-SHA256 implementation for runtimes
    # where the 4-argument Rfc2898DeriveBytes(byte[], byte[], int, HashAlgorithmName) constructor is unavailable
    param(
        [Parameter(Mandatory = $true)][byte[]]$Password,
        [Parameter(Mandatory = $true)][byte[]]$Salt,
        [Parameter(Mandatory = $true)][ValidateRange(1, 10000000)][int]$Iterations,
        [Parameter(Mandatory = $true)][ValidateRange(1, 1024)][int]$ByteCount
    )

    $hmac = New-Object System.Security.Cryptography.HMACSHA256(, $Password)
    [byte[]]$output = New-Object byte[] $ByteCount
    [byte[]]$saltBlock = New-Object byte[] ($Salt.Length + 4)
    [byte[]]$u = $null
    [byte[]]$t = $null
    try {
        [Array]::Copy($Salt, 0, $saltBlock, 0, $Salt.Length)
        [int]$blockCount = [Math]::Ceiling($ByteCount / 32.0)
        [int]$offset = 0

        for ($block = 1; $block -le $blockCount; $block++) {
            $saltBlock[$Salt.Length]     = [byte](($block -shr 24) -band 0xFF)
            $saltBlock[$Salt.Length + 1] = [byte](($block -shr 16) -band 0xFF)
            $saltBlock[$Salt.Length + 2] = [byte](($block -shr 8) -band 0xFF)
            $saltBlock[$Salt.Length + 3] = [byte]($block -band 0xFF)

            $u = $hmac.ComputeHash($saltBlock)
            $t = New-Object byte[] $u.Length
            [Array]::Copy($u, 0, $t, 0, $u.Length)

            for ($iter = 2; $iter -le $Iterations; $iter++) {
                [byte[]]$nextU = $hmac.ComputeHash($u)
                Clear-VaultBytes $u
                $u = $nextU
                for ($k = 0; $k -lt $t.Length; $k++) {
                    $t[$k] = [byte]($t[$k] -bxor $u[$k])
                }
            }

            [int]$copyLen = [Math]::Min(32, $ByteCount - $offset)
            [Array]::Copy($t, 0, $output, $offset, $copyLen)
            $offset += $copyLen
            Clear-VaultBytes $u
            Clear-VaultBytes $t
        }
        return $output
    }
    finally {
        $hmac.Dispose()
        Clear-VaultBytes $saltBlock
        Clear-VaultBytes $u
        Clear-VaultBytes $t
    }
}

function Get-VaultMasterBytes {
    # Derives 64 master key bytes (32B AES + 32B HMAC) via PBKDF2 with 100,000 iterations.
    # Algorithm 2 uses PBKDF2-HMAC-SHA256; Algorithm 1 preserves backward-compatible PBKDF2-HMAC-SHA1 reading.
    param(
        [Parameter(Mandatory = $true)][string]$SeedPath,
        [ValidateSet(1, 2)][int]$Algorithm = $script:VaultDefaultAlgorithm
    )

    if (-not (Test-Path -LiteralPath $SeedPath -PathType Leaf)) {
        throw "Master seed file is missing at: $SeedPath"
    }
    [byte[]]$rawSeed = [System.IO.File]::ReadAllBytes($SeedPath)
    try {
        if ($rawSeed.Length -ne 64) { throw "Invalid seed length. Expected 64 bytes." }
        [byte[]]$salt = $rawSeed[0..31]
        [byte[]]$secret = $rawSeed[32..63]
        try {
            if ($Algorithm -eq 1) {
                $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($secret, $salt, 100000)
                try { return $pbkdf2.GetBytes(64) } finally { $pbkdf2.Dispose() }
            }

            $pbkdf2Sha256 = $null
            try {
                $pbkdf2Sha256 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
                    $secret,
                    $salt,
                    100000,
                    [System.Security.Cryptography.HashAlgorithmName]::SHA256
                )
                return $pbkdf2Sha256.GetBytes(64)
            }
            catch {
                return (Invoke-VaultPbkdf2Sha256 -Password $secret -Salt $salt -Iterations 100000 -ByteCount 64)
            }
            finally {
                if ($null -ne $pbkdf2Sha256) { $pbkdf2Sha256.Dispose() }
            }
        }
        finally {
            Clear-VaultBytes $salt
            Clear-VaultBytes $secret
        }
    }
    finally { Clear-VaultBytes $rawSeed }
}

function New-VaultSeedFile {
    # Generates 64 high-entropy random bytes and writes to a new seed file
    param([Parameter(Mandatory = $true)][string]$Path)

    [byte[]]$seed = New-Object byte[] 64
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($seed)
        $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $stream.Write($seed, 0, $seed.Length)
            $stream.Flush($true)
        }
        finally { $stream.Dispose() }
    }
    finally {
        $rng.Dispose()
        Clear-VaultBytes $seed
    }
}

function Set-VaultSeedAttributes {
    # Sets Hidden and System file attributes to reduce accidental exposure/deletion
    param([Parameter(Mandatory = $true)][string]$SeedPath)

    if (-not (Test-Path -LiteralPath $SeedPath -PathType Leaf)) {
        throw "Cannot set attributes on a missing seed: $SeedPath"
    }
    $item = Get-Item -LiteralPath $SeedPath -Force
    $item.Attributes = $item.Attributes -bor [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System
}

function Assert-VaultSafeLogging {
    # Inspects registry policy (including WOW6432Node and ScriptBlockLogging) and active global transcripts
    [CmdletBinding()]
    param([switch]$AllowUnsafeLogging)

    if ($AllowUnsafeLogging) { return $true }

    $transcriptionPaths = @(
        "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription",
        "HKCU:\Software\Policies\Microsoft\Windows\PowerShell\Transcription",
        "HKLM:\Software\WOW6432Node\Policies\Microsoft\Windows\PowerShell\Transcription",
        "HKCU:\Software\WOW6432Node\Policies\Microsoft\Windows\PowerShell\Transcription"
    )
    foreach ($path in $transcriptionPaths) {
        $policy = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
        if (
            $null -ne $policy -and
            ($policy.PSObject.Properties.Name -contains "EnableTranscripting") -and
            [int]$policy.EnableTranscripting -eq 1
        ) {
            throw "PowerShell transcription policy is enabled at '$path'. Secret operations are blocked."
        }
    }

    $scriptBlockPaths = @(
        "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "HKLM:\Software\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "HKCU:\Software\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    )
    foreach ($path in $scriptBlockPaths) {
        $sbPolicy = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
        if ($null -ne $sbPolicy) {
            $sbEnabled = ($sbPolicy.PSObject.Properties.Name -contains "EnableScriptBlockLogging") -and ([int]$sbPolicy.EnableScriptBlockLogging -eq 1)
            $sbInvocationEnabled = ($sbPolicy.PSObject.Properties.Name -contains "EnableScriptBlockInvocationLogging") -and ([int]$sbPolicy.EnableScriptBlockInvocationLogging -eq 1)
            if ($sbEnabled -or $sbInvocationEnabled) {
                throw "PowerShell script block logging policy is enabled at '$path'. Secret operations are blocked."
            }
        }
    }

    $tVar = Get-Variable -Name Transcript -Scope Global -ErrorAction SilentlyContinue
    if ($null -ne $tVar -and $tVar.Value) {
        throw "An active transcript indicator was detected. Stop transcription before running vault operations."
    }
    return $true
}

# ==============================================================================
# SECTION 2: CONCURRENCY LOCKING & LOCALE-INDEPENDENT ACL UTILITIES
# ==============================================================================

function Open-VaultLock {
    # Acquires exclusive .lock file with deadline retries to prevent race conditions
    param([Parameter(Mandatory = $true)][string]$VaultPath, [int]$TimeoutSeconds = 30)

    $lockPath = "$VaultPath.lock"
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            return [System.IO.File]::Open($lockPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        }
        catch [System.IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) { throw "Timed out acquiring vault lock: $lockPath" }
            Start-Sleep -Milliseconds 100
        }
    } while ($true)
}

function Write-VaultFileRaw {
    # Writes raw payload bytes to a specified file path with exclusive access
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][byte[]]$Payload)

    $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($Payload, 0, $Payload.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
}

function Resolve-VaultIdentitySid {
    # Translates a SecurityIdentifier, SID string, or account name into a locale-independent SecurityIdentifier
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

function Get-VaultDefaultAuthorizedSids {
    # Returns deduplicated well-known SIDs for CurrentUser, LocalSystem (S-1-5-18), and BuiltinAdministrators (S-1-5-32-544)
    param()

    $sids = New-Object System.Collections.Generic.List[System.Security.Principal.SecurityIdentifier]
    $seen = @{}

    $currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $adminsSid = New-Object System.Security.Principal.SecurityIdentifier(
        [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,
        $null
    )
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier(
        [System.Security.Principal.WellKnownSidType]::LocalSystemSid,
        $null
    )

    foreach ($candidate in @($currentUserSid, $adminsSid, $systemSid)) {
        if ($null -ne $candidate -and -not $seen.ContainsKey($candidate.Value)) {
            $seen[$candidate.Value] = $true
            $sids.Add($candidate)
        }
    }
    return $sids.ToArray()
}

function Protect-VaultDirectoryAcl {
    # Restricts a vault or backup directory ACL exclusively to Current Identity, SYSTEM (S-1-5-18), and Administrators (S-1-5-32-544)
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $sec = New-Object System.Security.AccessControl.DirectorySecurity
    $sec.SetAccessRuleProtection($true, $false)

    $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagate = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow

    foreach ($sid in @(Get-VaultDefaultAuthorizedSids)) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $rights, $inherit, $propagate, $allow)
        $sec.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $resolved -AclObject $sec
}

function Protect-VaultFileAcl {
    # Restricts a vault, seed, or recovery file ACL exclusively to Current Identity, SYSTEM (S-1-5-18), and Administrators (S-1-5-32-544)
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $sec = New-Object System.Security.AccessControl.FileSecurity
    $sec.SetAccessRuleProtection($true, $false)

    $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $allow = [System.Security.AccessControl.AccessControlType]::Allow

    foreach ($sid in @(Get-VaultDefaultAuthorizedSids)) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $rights, $allow)
        $sec.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $resolved -AclObject $sec
}

function Protect-VaultBackupDirectory {
    # Locks backup directory ACLs exclusively to Current Identity, SYSTEM, and Administrators via well-known SIDs
    param([Parameter(Mandatory = $true)][string]$Path)
    Protect-VaultDirectoryAcl -Path $Path
}

# ==============================================================================
# SECTION 3: PAYLOAD ENCRYPTION, DECRYPTION & SCHEMAS
# ==============================================================================

function ConvertTo-VaultPayload {
    # Builds JSON envelope, encrypts AES-256-CBC, and prepends magic header + HMAC tag
    param(
        [AllowEmptyCollection()][array]$Entries = @(),
        [Parameter(Mandatory = $true)][byte[]]$MasterBytes,
        [string]$VaultId = [guid]::NewGuid().ToString("D"),
        [string]$KeyId = [guid]::NewGuid().ToString("D"),
        [long]$Generation = 1,
        [ValidateSet(1, 2)][int]$Algorithm = $script:VaultDefaultAlgorithm
    )

    foreach ($entry in $Entries) {
        if ($entry.PSObject.Properties.Name -contains "ExpiresUtc") {
            $entry.PSObject.Properties.Remove("ExpiresUtc")
        }
    }

    $envelope = [ordered]@{
        SchemaVersion = 3
        VaultId       = $VaultId
        KeyId         = $KeyId
        Generation    = $Generation
        WrittenUtc    = [DateTime]::UtcNow.ToString("o")
        Entries       = @($Entries)
    }

    $json = $envelope | ConvertTo-Json -Depth 8 -Compress
    [byte[]]$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    [byte[]]$aesKey = $MasterBytes[0..31]
    [byte[]]$hmacKey = $MasterBytes[32..63]

    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.Key = $aesKey
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.GenerateIV()

        $encryptor = $aes.CreateEncryptor()
        try { [byte[]]$cipher = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length) }
        finally { $encryptor.Dispose() }

        # Header Structure: [Magic 4B][Version 1B][Algorithm 1B][Reserved 2B][IV 16B]
        [byte[]]$header = New-Object byte[] $script:VaultHeaderLength
        [Array]::Copy($script:VaultMagic, 0, $header, 0, 4)
        $header[4] = $script:VaultVersion
        $header[5] = [byte]$Algorithm
        [Array]::Copy($aes.IV, 0, $header, 8, 16)

        # Authenticate Header + Ciphertext with HMAC-SHA256
        $authenticated = $header + $cipher
        $hmac = New-Object System.Security.Cryptography.HMACSHA256(, $hmacKey)
        try { [byte[]]$tag = $hmac.ComputeHash($authenticated) }
        finally {
            $hmac.Dispose()
            Clear-VaultBytes $authenticated
        }

        return ($header + $tag + $cipher)
    }
    finally {
        $aes.Dispose()
        Clear-VaultBytes $plainBytes
        Clear-VaultBytes $aesKey
        Clear-VaultBytes $hmacKey
        $json = $null
    }
}

function ConvertFrom-VaultPayload {
    # Validates magic header, checks HMAC tag in constant time, decrypts AES, & parses envelope
    param([Parameter(Mandatory = $true)][byte[]]$Payload, [Parameter(Mandatory = $true)][byte[]]$MasterBytes, [switch]$ReturnEnvelope)

    if ($Payload.Length -lt ($script:VaultHeaderLength + $script:VaultTagLength + 16)) { throw "Truncated binary payload." }
    if ($Payload.Length -gt $script:VaultMaxBytes) { throw "Payload exceeds 10 MB limit." }
    for ($i = 0; $i -lt 4; $i++) {
        if ($Payload[$i] -ne $script:VaultMagic[$i]) { throw "Magic header mismatch." }
    }
    if ($Payload[4] -ne $script:VaultVersion -or ($Payload[5] -ne 1 -and $Payload[5] -ne 2)) {
        throw "Unsupported version/algorithm."
    }

    [byte[]]$header = $Payload[0..($script:VaultHeaderLength - 1)]
    [byte[]]$storedTag = $Payload[$script:VaultHeaderLength..($script:VaultHeaderLength + 31)]
    [byte[]]$cipher = $Payload[($script:VaultHeaderLength + $script:VaultTagLength)..($Payload.Length - 1)]
    [byte[]]$aesKey = $MasterBytes[0..31]
    [byte[]]$hmacKey = $MasterBytes[32..63]

    try {
        # Verify HMAC tag in constant time
        $hmac = New-Object System.Security.Cryptography.HMACSHA256(, $hmacKey)
        try { [byte[]]$computedTag = $hmac.ComputeHash($header + $cipher) }
        finally { $hmac.Dispose() }

        try {
            if (-not (Test-VaultFixedTimeEqual $storedTag $computedTag)) {
                throw "Integrity check failed! Key mismatch or payload tampered."
            }
        }
        finally { Clear-VaultBytes $computedTag }

        # Decrypt AES-256-CBC payload
        $aes = [System.Security.Cryptography.Aes]::Create()
        try {
            $aes.Key = $aesKey; $aes.IV = $header[8..23]
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

            $dec = $aes.CreateDecryptor()
            try { [byte[]]$plainBytes = $dec.TransformFinalBlock($cipher, 0, $cipher.Length) }
            finally { $dec.Dispose() }
        }
        finally { $aes.Dispose() }

        # Parse JSON envelope schema
        try {
            $json = [System.Text.Encoding]::UTF8.GetString($plainBytes)
            $envelope = $json | ConvertFrom-Json

            if ($envelope.SchemaVersion -ne 3 -or $null -eq $envelope.Entries) { throw "Invalid envelope schema." }
            [guid]::Parse([string]$envelope.VaultId) | Out-Null

            if ($envelope.PSObject.Properties.Name -contains "KeyId") { [guid]::Parse([string]$envelope.KeyId) | Out-Null }
            if ($envelope.PSObject.Properties.Name -contains "Generation" -and [long]$envelope.Generation -lt 1) { throw "Invalid generation counter." }

            Test-VaultEntries -Entries @($envelope.Entries) | Out-Null
            if ($ReturnEnvelope) { return $envelope }
            return @($envelope.Entries)
        }
        finally {
            Clear-VaultBytes $plainBytes
            $json = $null
        }
    }
    finally {
        Clear-VaultBytes $header; Clear-VaultBytes $storedTag; Clear-VaultBytes $cipher; Clear-VaultBytes $aesKey; Clear-VaultBytes $hmacKey
    }
}

function Test-VaultEntries {
    # Validates credential entry schema, required fields, and Regex ID patterns
    param([AllowEmptyCollection()][array]$Entries = @())

    $ids = @{}
    foreach ($entry in $Entries) {
        foreach ($required in @("Id", "Username", "Password", "Enabled")) {
            if (-not ($entry.PSObject.Properties.Name -contains $required)) { throw "Entry missing field '$required'." }
        }
        $id = [string]$entry.Id
        if ($id -notmatch '^[A-Za-z0-9_.-]{1,64}$') { throw "Invalid ID format: '$id'." }
        if ($ids.ContainsKey($id)) { throw "Duplicate ID: $id" }
        $ids[$id] = $true

        if ([string]::IsNullOrWhiteSpace([string]$entry.Username) -or ([string]$entry.Username).Length -gt 512) { throw "Invalid username for '$id'." }
        if ($null -eq $entry.Password -or ([string]$entry.Password).Length -gt 4096) { throw "Invalid password size for '$id'." }
    }
    return $true
}

function Read-VaultEnvelope {
    # Enforces safe logging policy, supports pre-derived MasterBytes, and retries once (150ms) on transient mid-swap reads
    param(
        [Parameter(Mandatory = $true)][string]$VaultPath,
        [Parameter(Mandatory = $true)][string]$SeedPath,
        [AllowNull()][byte[]]$MasterBytes = $null,
        [ValidateSet(1, 2)][int]$MasterBytesAlgorithm = $script:VaultDefaultAlgorithm
    )

    Assert-VaultSafeLogging | Out-Null

    $lastError = $null
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        [byte[]]$payload = $null
        [byte[]]$localMaster = $null
        try {
            $payload = [System.IO.File]::ReadAllBytes($VaultPath)
            [int]$payloadAlgorithm = if (
                $null -ne $payload -and
                $payload.Length -ge 6 -and
                ($payload[5] -eq 1 -or $payload[5] -eq 2)
            ) {
                [int]$payload[5]
            }
            else {
                $script:VaultDefaultAlgorithm
            }

            [byte[]]$effectiveMaster = $null
            if (
                $attempt -eq 1 -and
                $null -ne $MasterBytes -and
                $MasterBytes.Length -eq 64 -and
                $payloadAlgorithm -eq $MasterBytesAlgorithm
            ) {
                $effectiveMaster = $MasterBytes
            }
            else {
                $localMaster = Get-VaultMasterBytes -SeedPath $SeedPath -Algorithm $payloadAlgorithm
                $effectiveMaster = $localMaster
            }

            return (ConvertFrom-VaultPayload -Payload $payload -MasterBytes $effectiveMaster -ReturnEnvelope)
        }
        catch {
            $lastError = $_
            if ($attempt -lt 2) {
                Start-Sleep -Milliseconds 150
            }
        }
        finally {
            Clear-VaultBytes $payload
            Clear-VaultBytes $localMaster
        }
    }
    throw $lastError
}

function Read-VaultEntries {
    param(
        [Parameter(Mandatory = $true)][string]$VaultPath,
        [Parameter(Mandatory = $true)][string]$SeedPath,
        [AllowNull()][byte[]]$MasterBytes = $null,
        [ValidateSet(1, 2)][int]$MasterBytesAlgorithm = $script:VaultDefaultAlgorithm
    )
    return @((Read-VaultEnvelope -VaultPath $VaultPath -SeedPath $SeedPath -MasterBytes $MasterBytes -MasterBytesAlgorithm $MasterBytesAlgorithm).Entries)
}

function Write-VaultEntries {
    # Atomic temp-write + pre-commit round-trip verification + atomic replace reusing derived MasterBytes
    param(
        [Parameter(Mandatory = $true)][string]$VaultPath,
        [Parameter(Mandatory = $true)][string]$SeedPath,
        [AllowEmptyCollection()][array]$Entries = @(),
        [switch]$LockAlreadyHeld,
        [AllowNull()][byte[]]$MasterBytes = $null,
        [ValidateSet(1, 2)][int]$Algorithm = $script:VaultDefaultAlgorithm
    )

    $lock = $null
    [byte[]]$localMaster = $null
    [byte[]]$payload = $null
    $curEnv = $null
    $verifiedEntries = $null
    $temporary = "$VaultPath.$([guid]::NewGuid().ToString('N')).tmp"
    $backup = "$VaultPath.bak"

    try {
        if (-not $LockAlreadyHeld) { $lock = Open-VaultLock -VaultPath $VaultPath }
        [byte[]]$effectiveMaster = if ($null -ne $MasterBytes -and $MasterBytes.Length -eq 64) {
            $MasterBytes
        }
        else {
            $localMaster = Get-VaultMasterBytes -SeedPath $SeedPath -Algorithm $Algorithm
            $localMaster
        }

        $vId = [guid]::NewGuid().ToString("D")
        $kId = [guid]::NewGuid().ToString("D")
        [long]$gen = 1

        if (Test-Path -LiteralPath $VaultPath) {
            $curEnv = Read-VaultEnvelope -VaultPath $VaultPath -SeedPath $SeedPath -MasterBytes $effectiveMaster -MasterBytesAlgorithm $Algorithm
            $vId = [string]$curEnv.VaultId
            if ($curEnv.PSObject.Properties.Name -contains "KeyId" -and $curEnv.KeyId) { $kId = [string]$curEnv.KeyId }
            $gen = if ($curEnv.PSObject.Properties.Name -contains "Generation") { [long]$curEnv.Generation + 1 } else { 2 }
        }

        Test-VaultEntries -Entries $Entries | Out-Null
        $payload = ConvertTo-VaultPayload -Entries $Entries -MasterBytes $effectiveMaster -VaultId $vId -KeyId $kId -Generation $gen -Algorithm $Algorithm
        Write-VaultFileRaw -Path $temporary -Payload $payload
        Protect-VaultFileAcl -Path $temporary

        # Pre-commit verification: re-read and decrypt temp payload in memory before replacing live file
        [byte[]]$verification = [System.IO.File]::ReadAllBytes($temporary)
        try {
            $verifiedEntries = @(ConvertFrom-VaultPayload -Payload $verification -MasterBytes $effectiveMaster)
        }
        finally {
            Clear-VaultBytes $verification
            Clear-VaultEntriesMemory -Entries $verifiedEntries
        }

        # Atomic File Replace
        if (Test-Path -LiteralPath $VaultPath) {
            [System.IO.File]::Replace($temporary, $VaultPath, $backup, $true)
            if (Test-Path -LiteralPath $backup) { Protect-VaultFileAcl -Path $backup }
        }
        else {
            [System.IO.File]::Move($temporary, $VaultPath)
        }
        Protect-VaultFileAcl -Path $VaultPath
    }
    finally {
        if ($null -ne $curEnv) { Clear-VaultEntriesMemory -Entries @($curEnv.Entries) }
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
        Clear-VaultBytes $payload
        Clear-VaultBytes $localMaster
        if ($null -ne $lock) { $lock.Dispose() }
    }
}

# ==============================================================================
# SECTION 4: CREDENTIAL CRUD CMDLETS
# ==============================================================================

function Initialize-Vault {
    # Initializes a new master seed and empty encrypted vault file pair with immediate NTFS ACL lockdown
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$VaultPath, [Parameter(Mandatory = $true)][string]$SeedPath)

    $parent = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($VaultPath))
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    if (Test-Path -LiteralPath $SeedPath) { throw "Refusing to overwrite existing seed: $SeedPath" }
    if (Test-Path -LiteralPath $VaultPath) { throw "Refusing to overwrite existing vault: $VaultPath" }

    $seedParent = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($SeedPath))
    if (-not (Test-Path -LiteralPath $seedParent -PathType Container)) { New-Item -ItemType Directory -Path $seedParent -Force | Out-Null }

    Protect-VaultDirectoryAcl -Path $parent
    if ($seedParent -ne $parent) {
        Protect-VaultDirectoryAcl -Path $seedParent
    }

    New-VaultSeedFile -Path $SeedPath
    try {
        Protect-VaultFileAcl -Path $SeedPath
        Set-VaultSeedAttributes -SeedPath $SeedPath
        Write-VaultEntries -VaultPath $VaultPath -SeedPath $SeedPath -Entries @()
        Protect-VaultFileAcl -Path $VaultPath
    }
    catch {
        Remove-Item -LiteralPath $SeedPath -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Set-VaultCredential {
    # Adds or updates a credential entry in the vault using a single KDF derivation per lock scope
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$VaultPath,
        [Parameter(Mandatory = $true)][string]$SeedPath,
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9_.-]{1,64}$')][string]$CredentialId,
        [Parameter(Mandatory = $true)][string]$Username,
        [Parameter(Mandatory = $true)][System.Security.SecureString]$Password,
        [string]$Description = "",
        [bool]$Enabled = $true
    )

    Assert-VaultSafeLogging | Out-Null
    $lock = Open-VaultLock -VaultPath $VaultPath
    $bstr = [System.IntPtr]::Zero
    $plainPassword = $null
    [byte[]]$master = $null
    $entries = @()

    try {
        $master = Get-VaultMasterBytes -SeedPath $SeedPath -Algorithm $script:VaultDefaultAlgorithm
        $entries = @(Read-VaultEntries -VaultPath $VaultPath -SeedPath $SeedPath -MasterBytes $master -MasterBytesAlgorithm $script:VaultDefaultAlgorithm)
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $now = [DateTime]::UtcNow.ToString("o")

        $existing = @($entries | Where-Object { $_.Id -eq $CredentialId })
        if ($existing.Count -gt 1) { throw "Duplicate credential IDs: $CredentialId" }
        if ($existing.Count -eq 1) {
            $existing[0].Username = $Username; $existing[0].Password = $plainPassword; $existing[0].Description = $Description; $existing[0].Enabled = $Enabled; $existing[0].LastUpdatedUtc = $now
        }
        else {
            $entries += [pscustomobject][ordered]@{
                Id = $CredentialId; Username = $Username; Password = $plainPassword; Description = $Description; Enabled = $Enabled; CreatedUtc = $now; LastUpdatedUtc = $now
            }
        }
        Write-VaultEntries -VaultPath $VaultPath -SeedPath $SeedPath -Entries $entries -LockAlreadyHeld -MasterBytes $master -Algorithm $script:VaultDefaultAlgorithm
    }
    finally {
        if ($bstr -ne [System.IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        Clear-VaultEntriesMemory -Entries $entries
        Clear-VaultBytes $master
        $plainPassword = $null; $entries = $null; $lock.Dispose()
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

function Get-VaultCredential {
    # Retrieves a credential as a PSCredential object and scrubs deserialized entry passwords in finally
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$VaultPath, [Parameter(Mandatory = $true)][string]$SeedPath, [Parameter(Mandatory = $true)][string]$CredentialId)

    Assert-VaultSafeLogging | Out-Null
    $entries = @(Read-VaultEntries -VaultPath $VaultPath -SeedPath $SeedPath)
    try {
        $matches = @($entries | Where-Object { $_.Id -eq $CredentialId })
        if ($matches.Count -ne 1) { throw "Credential '$CredentialId' was not found or is duplicated." }
        if (-not [bool]$matches[0].Enabled) { throw "Credential '$CredentialId' is disabled." }
        $securePassword = ConvertTo-SecureString ([string]$matches[0].Password) -AsPlainText -Force
        return New-Object System.Management.Automation.PSCredential([string]$matches[0].Username, $securePassword)
    }
    finally {
        Clear-VaultEntriesMemory -Entries $entries
        $entries = $null
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

function Get-VaultSummary {
    # Returns a list of non-sensitive credential metadata (excluding password values)
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$VaultPath, [Parameter(Mandatory = $true)][string]$SeedPath)

    $entries = @(Read-VaultEntries -VaultPath $VaultPath -SeedPath $SeedPath)
    try { return $entries | Select-Object Id, Username, Description, Enabled, CreatedUtc, LastUpdatedUtc }
    finally {
        Clear-VaultEntriesMemory -Entries $entries
        $entries = $null
    }
}

function Remove-VaultCredential {
    # Removes a credential entry from the vault by ID using a single KDF derivation per lock scope
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$VaultPath, [Parameter(Mandatory = $true)][string]$SeedPath, [Parameter(Mandatory = $true)][string]$CredentialId)

    $lock = Open-VaultLock -VaultPath $VaultPath
    [byte[]]$master = $null
    $entries = @()
    $filtered = @()
    try {
        $master = Get-VaultMasterBytes -SeedPath $SeedPath -Algorithm $script:VaultDefaultAlgorithm
        $entries = @(Read-VaultEntries -VaultPath $VaultPath -SeedPath $SeedPath -MasterBytes $master -MasterBytesAlgorithm $script:VaultDefaultAlgorithm)
        $filtered = @($entries | Where-Object { $_.Id -ne $CredentialId })
        if ($filtered.Count -eq $entries.Count) { throw "Credential '$CredentialId' was not found." }
        Write-VaultEntries -VaultPath $VaultPath -SeedPath $SeedPath -Entries $filtered -LockAlreadyHeld -MasterBytes $master -Algorithm $script:VaultDefaultAlgorithm
    }
    finally {
        Clear-VaultEntriesMemory -Entries $entries
        Clear-VaultEntriesMemory -Entries $filtered
        Clear-VaultBytes $master
        $entries = $null; $filtered = $null; $lock.Dispose()
    }
}

# ==============================================================================
# SECTION 5: LIFECYCLE OPERATIONS (BACKUP, SEED ROTATION & RESTORE)
# ==============================================================================

function Backup-Vault {
    # Creates a timestamped backup pair with ACL lockdown and retention purging
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$VaultPath, [Parameter(Mandatory = $true)][string]$SeedPath, [Parameter(Mandatory = $true)][string]$BackupDirectory, [ValidateRange(1, 100)][int]$RetentionCount = 10)

    $lock = Open-VaultLock -VaultPath $VaultPath
    $entries = @()
    try {
        $entries = @(Read-VaultEntries -VaultPath $VaultPath -SeedPath $SeedPath)
        if (-not (Test-Path -LiteralPath $BackupDirectory)) { New-Item -ItemType Directory -Path $BackupDirectory -Force | Out-Null }
        Protect-VaultBackupDirectory -Path $BackupDirectory

        $stamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssfffZ")
        $vaultBackup = Join-Path $BackupDirectory "vault-$stamp.bin"
        $seedBackup = Join-Path $BackupDirectory "seed-$stamp.bin"

        Copy-Item -LiteralPath $VaultPath -Destination $vaultBackup
        Copy-Item -LiteralPath $SeedPath -Destination $seedBackup
        Protect-VaultFileAcl -Path $vaultBackup
        Protect-VaultFileAcl -Path $seedBackup
        Set-VaultSeedAttributes -SeedPath $seedBackup

        # Enforce retention policy
        $pairs = @(Get-ChildItem -LiteralPath $BackupDirectory -Filter "vault-*.bin" | Sort-Object Name -Descending)
        foreach ($oldVault in @($pairs | Select-Object -Skip $RetentionCount)) {
            $oldStamp = $oldVault.BaseName.Substring(6)
            $oldSeed = Join-Path $BackupDirectory "seed-$oldStamp.bin"
            Remove-Item -LiteralPath $oldVault.FullName -Force
            if (Test-Path -LiteralPath $oldSeed) { Remove-Item -LiteralPath $oldSeed -Force }
        }
        return [pscustomobject]@{ VaultBackup = $vaultBackup; SeedBackup = $seedBackup }
    }
    finally {
        Clear-VaultEntriesMemory -Entries $entries
        $entries = $null
        $lock.Dispose()
    }
}

function Invoke-VaultAtomicSwap {
    # Helper for atomic replacement, ACL protection, and rollback of vault & seed pairs
    param(
        [string]$VaultPath, [string]$SeedPath,
        [string]$CandVault, [string]$CandSeed,
        [string]$VaultBakExt, [string]$SeedBakExt,
        [AllowNull()][byte[]]$MasterBytes = $null
    )
    $sRec = "$SeedPath.$SeedBakExt"; $vRec = "$VaultPath.$VaultBakExt"
    $verifiedEntries = $null
    Remove-Item -LiteralPath $sRec, $vRec -Force -ErrorAction SilentlyContinue
    try {
        [System.IO.File]::Replace($CandSeed, $SeedPath, $sRec, $true)
        [System.IO.File]::Replace($CandVault, $VaultPath, $vRec, $true)
        Protect-VaultFileAcl -Path $SeedPath
        Protect-VaultFileAcl -Path $VaultPath
        Set-VaultSeedAttributes -SeedPath $SeedPath
        if (Test-Path -LiteralPath $sRec) {
            Protect-VaultFileAcl -Path $sRec
            Set-VaultSeedAttributes -SeedPath $sRec
        }
        if (Test-Path -LiteralPath $vRec) {
            Protect-VaultFileAcl -Path $vRec
        }
        $verifiedEntries = @(Read-VaultEntries -VaultPath $VaultPath -SeedPath $SeedPath -MasterBytes $MasterBytes)
        return [pscustomobject]@{ SeedRecovery = $sRec; VaultRecovery = $vRec }
    }
    catch {
        if (Test-Path -LiteralPath $sRec) { Copy-Item -LiteralPath $sRec -Destination $SeedPath -Force }
        if (Test-Path -LiteralPath $vRec) { Copy-Item -LiteralPath $vRec -Destination $VaultPath -Force }
        throw
    }
    finally {
        Clear-VaultEntriesMemory -Entries $verifiedEntries
    }
}

function Invoke-VaultSeedRotation {
    # Zero-downtime seed rotation under exclusive lock with automatic safety rollback and optional recovery artifact purge
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
    param(
        [Parameter(Mandatory = $true)][string]$VaultPath,
        [Parameter(Mandatory = $true)][string]$SeedPath,
        [switch]$RemoveRecoveryFiles
    )

    if (-not $PSCmdlet.ShouldProcess($VaultPath, "rotate seed and re-encrypt vault")) { return }

    $lock = Open-VaultLock -VaultPath $VaultPath
    $candSeed = "$SeedPath.$([guid]::NewGuid().ToString('N')).tmp"
    $candVault = "$VaultPath.$([guid]::NewGuid().ToString('N')).tmp"
    [byte[]]$newMaster = $null; [byte[]]$newPayload = $null
    $curEnv = $null
    $verifiedEntries = $null

    try {
        $curEnv = Read-VaultEnvelope -VaultPath $VaultPath -SeedPath $SeedPath
        New-VaultSeedFile -Path $candSeed
        Protect-VaultFileAcl -Path $candSeed
        $newMaster = Get-VaultMasterBytes -SeedPath $candSeed -Algorithm $script:VaultDefaultAlgorithm
        $nextGen = if ($curEnv.PSObject.Properties.Name -contains "Generation") { [long]$curEnv.Generation + 1 } else { 2 }

        $newPayload = ConvertTo-VaultPayload -Entries @($curEnv.Entries) -MasterBytes $newMaster -VaultId ([string]$curEnv.VaultId) -KeyId ([guid]::NewGuid().ToString("D")) -Generation $nextGen -Algorithm $script:VaultDefaultAlgorithm
        Write-VaultFileRaw -Path $candVault -Payload $newPayload
        Protect-VaultFileAcl -Path $candVault

        # Pre-commit verify candidate pair
        [byte[]]$verification = [System.IO.File]::ReadAllBytes($candVault)
        try {
            $verifiedEntries = @(ConvertFrom-VaultPayload -Payload $verification -MasterBytes $newMaster)
        }
        finally {
            Clear-VaultBytes $verification
            Clear-VaultEntriesMemory -Entries $verifiedEntries
        }

        $swap = Invoke-VaultAtomicSwap -VaultPath $VaultPath -SeedPath $SeedPath -CandVault $candVault -CandSeed $candSeed -VaultBakExt "rotation.bak" -SeedBakExt "rotation.bak" -MasterBytes $newMaster
        if ($RemoveRecoveryFiles) {
            foreach ($rec in @($swap.SeedRecovery, $swap.VaultRecovery)) {
                if (-not [string]::IsNullOrWhiteSpace($rec) -and (Test-Path -LiteralPath $rec)) {
                    Remove-Item -LiteralPath $rec -Force -ErrorAction Stop
                }
            }
            return [pscustomobject]@{
                SeedRecovery    = $null
                VaultRecovery   = $null
                RecoveryRemoved = $true
            }
        }
        return $swap
    }
    finally {
        if ($null -ne $curEnv) { Clear-VaultEntriesMemory -Entries @($curEnv.Entries) }
        foreach ($t in @($candSeed, $candVault)) { if (Test-Path -LiteralPath $t) { Remove-Item -LiteralPath $t -Force -ErrorAction SilentlyContinue } }
        Clear-VaultBytes $newMaster; Clear-VaultBytes $newPayload; $lock.Dispose()
    }
}

function Restore-Vault {
    # Restores a validated vault and seed backup pair after verifying schema identity and generation
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
    param(
        [Parameter(Mandatory = $true)][string]$VaultPath,
        [Parameter(Mandatory = $true)][string]$SeedPath,
        [Parameter(Mandatory = $true)][string]$VaultBackup,
        [Parameter(Mandatory = $true)][string]$SeedBackup,
        [switch]$RemoveRecoveryFiles
    )

    if (-not $PSCmdlet.ShouldProcess($VaultPath, "restore vault and seed backup")) { return }

    $lock = Open-VaultLock -VaultPath $VaultPath
    $candVault = "$VaultPath.$([guid]::NewGuid().ToString('N')).restore.tmp"
    $candSeed = "$SeedPath.$([guid]::NewGuid().ToString('N')).restore.tmp"
    $candEnv = $null
    $liveEnv = $null

    try {
        Copy-Item -LiteralPath $VaultBackup -Destination $candVault
        Copy-Item -LiteralPath $SeedBackup -Destination $candSeed
        Protect-VaultFileAcl -Path $candVault
        Protect-VaultFileAcl -Path $candSeed
        $candEnv = Read-VaultEnvelope -VaultPath $candVault -SeedPath $candSeed

        $swap = Invoke-VaultAtomicSwap -VaultPath $VaultPath -SeedPath $SeedPath -CandVault $candVault -CandSeed $candSeed -VaultBakExt "pre-restore" -SeedBakExt "pre-restore"
        $liveEnv = Read-VaultEnvelope -VaultPath $VaultPath -SeedPath $SeedPath
        if ([string]$liveEnv.VaultId -ne [string]$candEnv.VaultId -or [long]$liveEnv.Generation -ne [long]$candEnv.Generation) {
            throw "Restored vault metadata does not match candidate envelope."
        }
        if ($RemoveRecoveryFiles) {
            foreach ($rec in @($swap.SeedRecovery, $swap.VaultRecovery)) {
                if (-not [string]::IsNullOrWhiteSpace($rec) -and (Test-Path -LiteralPath $rec)) {
                    Remove-Item -LiteralPath $rec -Force -ErrorAction Stop
                }
            }
            return [pscustomobject]@{
                SeedRecovery    = $null
                VaultRecovery   = $null
                RecoveryRemoved = $true
            }
        }
        return $swap
    }
    finally {
        if ($null -ne $candEnv) { Clear-VaultEntriesMemory -Entries @($candEnv.Entries) }
        if ($null -ne $liveEnv) { Clear-VaultEntriesMemory -Entries @($liveEnv.Entries) }
        foreach ($t in @($candVault, $candSeed)) { if (Test-Path -LiteralPath $t) { Remove-Item -LiteralPath $t -Force -ErrorAction SilentlyContinue } }
        $lock.Dispose()
    }
}
