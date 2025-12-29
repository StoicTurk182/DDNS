#Requires -Version 5.1
<#
.SYNOPSIS
    Cloudflare DDNS Update Script
.DESCRIPTION
    Updates Cloudflare DNS A record with current public IP.
    Designed for Windows scheduled task execution in double NAT environments.
#>

# ============================================
# CONFIGURATION - UPDATE THESE VALUES
# ============================================
$Config = @{
    ApiToken   = "YOUR_API_TOKEN_HERE"
    ZoneId     = "YOUR_ZONE_ID_HERE"
    RecordId   = "YOUR_RECORD_ID_HERE"
    RecordName = "home.yourdomain.com"
    TTL        = 300
    Proxied    = $false
    LogPath    = "C:\Scripts\Logs\cloudflare-ddns.log"
}
# ============================================

# Log rotation - runs before any logging
$MaxLogSizeMB = 5
if ((Test-Path $Config.LogPath) -and ((Get-Item $Config.LogPath).Length / 1MB) -gt $MaxLogSizeMB) {
    $ArchivePath = $Config.LogPath -replace '\.log$', "-$(Get-Date -Format 'yyyyMMdd').log"
    Move-Item -Path $Config.LogPath -Destination $ArchivePath -Force
}

# Ensure log directory exists
$LogDir = Split-Path -Parent $Config.LogPath
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $Config.LogPath -Append -Encoding UTF8
}

function Get-PublicIP {
    $IPServices = @(
        "https://api.ipify.org"
        "https://ifconfig.me/ip"
        "https://icanhazip.com"
    )
    
    foreach ($Service in $IPServices) {
        try {
            $IP = (Invoke-RestMethod -Uri $Service -TimeoutSec 10).Trim()
            if ($IP -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                return $IP
            }
        } catch {
            continue
        }
    }
    return $null
}

function Get-CloudflareDNS {
    $Headers = @{
        "Authorization" = "Bearer $($Config.ApiToken)"
        "Content-Type"  = "application/json"
    }
    
    $Uri = "https://api.cloudflare.com/client/v4/zones/$($Config.ZoneId)/dns_records/$($Config.RecordId)"
    
    try {
        $Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get
        if ($Response.success) {
            return $Response.result.content
        }
    } catch {
        Write-Log "ERROR: Failed to query Cloudflare - $($_.Exception.Message)"
    }
    return $null
}

function Update-CloudflareDNS {
    param([string]$NewIP)
    
    $Headers = @{
        "Authorization" = "Bearer $($Config.ApiToken)"
        "Content-Type"  = "application/json"
    }
    
    $Body = @{
        type    = "A"
        name    = $Config.RecordName
        content = $NewIP
        ttl     = $Config.TTL
        proxied = $Config.Proxied
    } | ConvertTo-Json
    
    $Uri = "https://api.cloudflare.com/client/v4/zones/$($Config.ZoneId)/dns_records/$($Config.RecordId)"
    
    try {
        $Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Put -Body $Body
        return $Response.success
    } catch {
        Write-Log "ERROR: Failed to update Cloudflare - $($_.Exception.Message)"
        return $false
    }
}

# Main execution
$CurrentIP = Get-PublicIP

if (-not $CurrentIP) {
    Write-Log "ERROR: Failed to retrieve public IP"
    exit 1
}

$DnsIP = Get-CloudflareDNS

if (-not $DnsIP) {
    Write-Log "ERROR: Failed to retrieve current DNS record"
    exit 1
}

if ($CurrentIP -eq $DnsIP) {
    Write-Log "INFO: No update required ($CurrentIP)"
    exit 0
}

Write-Log "INFO: IP changed from $DnsIP to $CurrentIP"

if (Update-CloudflareDNS -NewIP $CurrentIP) {
    Write-Log "SUCCESS: Updated $($Config.RecordName) to $CurrentIP"
    exit 0
} else {
    Write-Log "ERROR: Update failed"
    exit 1
}