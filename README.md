# DDNS
DDNS Automation Script

# Cloudflare DDNS - Windows Scheduled Task

This guide configures a PowerShell script to update Cloudflare DNS on workstation startup, login, and at regular intervals. Designed for double NAT environments where native gateway DDNS cannot detect the true public IP.

---

## Overview

In a double NAT environment, your gateway only sees the private IP assigned by the upstream router, not your actual public IP. Native DDNS on devices like UniFi gateways will report the wrong address.

This solution runs a PowerShell script on a Windows workstation that:

1. Queries an external service for the real public IP
2. Compares against the current Cloudflare DNS record
3. Updates Cloudflare if the IP has changed
4. Logs all activity for troubleshooting

---

## Network Topology

```
┌─────────────────────────────────────────────────────────────┐
│                     Your Network                            │
│                                                             │
│  Windows Workstation                                        │
│  └─ DDNS Script → Updates Cloudflare (home.orionnet.xyz)   │
│                                                             │
│  ISP Router (has public IP)                                │
│  └─ Port forward 1194/UDP → Gateway IP                     │
│                                                             │
│  UniFi Gateway (private IP from ISP router)                │
│  └─ OpenVPN Server listening on 1194                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                   VPN Client (external)                     │
│                                                             │
│  1. Resolves home.orionnet.xyz → gets current public IP    │
│  2. Connects to public IP:1194                             │
│  3. ISP router forwards to UniFi gateway                   │
│  4. OpenVPN authenticates and establishes tunnel           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Part 1: Cloudflare API Token

### Create Token

1. Log in to Cloudflare Dashboard
2. Navigate to **My Profile → API Tokens**
3. Click **Create Token**
4. Select **Edit zone DNS** template
5. Configure:

| Setting | Value |
|---------|-------|
| Token name | `DDNS Update` |
| Permissions | Zone → DNS → Edit |
| Zone Resources | Include → Specific zone → your domain |
| Client IP Filtering | Leave blank (required for DDNS) |
| TTL | Set expiry ~1 year |

6. Create and copy token immediately - store in password manager

### Verify Token

```powershell
Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/user/tokens/verify" -Headers @{"Authorization"="Bearer YOUR_TOKEN"}
```

---

## Part 2: Create DNS Record

The A record must exist before DDNS can update it.

### Via Cloudflare Dashboard

**DNS → Records → Add Record:**

| Field | Value |
|-------|-------|
| Type | A |
| Name | `home` (or your preferred subdomain) |
| Content | Your current public IP |
| Proxy status | DNS only (grey cloud) |
| TTL | Auto |

### Via API

```powershell
$token = "YOUR_TOKEN"
$zoneId = "YOUR_ZONE_ID"
$body = @{type="A"; name="home"; content="$(Invoke-RestMethod -Uri 'https://api.ipify.org')"; ttl=300; proxied=$false} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "https://api.cloudflare.com/client/v4/zones/$zoneId/dns_records" -Headers @{"Authorization"="Bearer $token"; "Content-Type"="application/json"} -Body $body
```

---

## Part 3: Retrieve Zone and Record IDs

```powershell
$token = "YOUR_TOKEN"
$zone = (Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones?name=yourdomain.com" -Headers @{"Authorization"="Bearer $token"}).result[0]
$record = (Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$($zone.id)/dns_records?name=home.yourdomain.com" -Headers @{"Authorization"="Bearer $token"}).result[0]
Write-Host "Zone ID: $($zone.id)`nRecord ID: $($record.id)"
```

Save these values for the script configuration.

---

## Part 4: Create the Script

### Create Directory

```powershell
New-Item -ItemType Directory -Path "C:\Scripts\Logs" -Force
```

### Script: C:\Scripts\Cloudflare-DDNS.ps1

```powershell
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
```

---

## Part 5: Test the Script

### Manual Execution

```powershell
& "C:\Scripts\Cloudflare-DDNS.ps1"
```

### Check Log Output

```powershell
Get-Content "C:\Scripts\Logs\cloudflare-ddns.log" -Tail 5
```

Expected output:

```
2025-12-28 16:24:59 - INFO: No update required (203.0.113.x)
```

### Verify DNS

```powershell
nslookup home.yourdomain.com 1.1.1.1
```

---

## Part 6: Create VBS Wrapper (Silent Execution)

PowerShell's `-WindowStyle Hidden` parameter does not reliably prevent window popups when triggered by Task Scheduler. A VBScript wrapper guarantees silent execution by launching PowerShell with a hidden window at the process level.

### Create VBS Wrapper

```powershell
'Set objShell = CreateObject("WScript.Shell")' | Out-File -FilePath "C:\Scripts\Cloudflare-DDNS.vbs" -Encoding ASCII
'objShell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""C:\Scripts\Cloudflare-DDNS.ps1""", 0, True' | Out-File -FilePath "C:\Scripts\Cloudflare-DDNS.vbs" -Append -Encoding ASCII
```

### Verify VBS Content

```powershell
Get-Content "C:\Scripts\Cloudflare-DDNS.vbs"
```

Expected output:

```vbscript
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""C:\Scripts\Cloudflare-DDNS.ps1""", 0, True
```

The `0` parameter specifies a hidden window. The `True` parameter waits for completion.

---

## Part 7: Create Scheduled Task

Run as Administrator:

```powershell
$Action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"C:\Scripts\Cloudflare-DDNS.vbs`""

$TriggerLogon = New-ScheduledTaskTrigger -AtLogOn
$TriggerStartup = New-ScheduledTaskTrigger -AtStartup

$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable

Register-ScheduledTask -TaskName "Cloudflare-DDNS" -Action $Action -Trigger $TriggerLogon, $TriggerStartup -Settings $Settings -Description "Updates Cloudflare DNS with current public IP"
```

### Add Periodic Trigger (Every 30 Minutes)

```powershell
$TriggerRepeat = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 30) -RepetitionDuration (New-TimeSpan -Days 365)

$Task = Get-ScheduledTask -TaskName "Cloudflare-DDNS"
$Task.Triggers += $TriggerRepeat
Set-ScheduledTask -InputObject $Task
```

---

## Part 8: Verify Scheduled Task

### Check Task Status

```powershell
Get-ScheduledTask -TaskName "Cloudflare-DDNS" | Select-Object TaskName, State
```

### Run Task Manually (No Window)

```powershell
Start-ScheduledTask -TaskName "Cloudflare-DDNS"
```

### Verify Execution

```powershell
Get-Content "C:\Scripts\Logs\cloudflare-ddns.log" -Tail 5
```

---

## Part 9: OpenVPN Client Configuration

UniFi's built-in OpenVPN server only accepts IP addresses in the server address field. Downloaded `.ovpn` configurations will contain the gateway's WAN IP, which is incorrect in double NAT.

### Modify Client Configuration

1. Download `.ovpn` from UniFi
2. Open in text editor
3. Find the `remote` line:
   ```
   remote 192.168.1.12 1194
   ```
4. Replace with your hostname:
   ```
   remote home.yourdomain.com 1194
   ```
5. Save and import to VPN client

### Full Tunnel vs Split Tunnel

The `redirect-gateway def1` directive controls traffic routing:

| Mode | Directive | Behaviour |
|------|-----------|-----------|
| Full tunnel | `redirect-gateway def1` present | All traffic routes via VPN |
| Split tunnel | Directive removed | Only LAN traffic routes via VPN |

Full tunnel is more secure on untrusted networks - all traffic is encrypted back to your home network.

---

## Part 10: Port Forwarding (Double NAT)

With double NAT, configure port forwarding on the upstream router:

| Field | Value |
|-------|-------|
| External Port | 1194 |
| Protocol | UDP |
| Internal IP | UniFi gateway WAN IP |
| Internal Port | 1194 |

If OpenVPN runs directly on the UniFi gateway, no port forward is needed on the gateway itself.

---

## Alternative: VPS-Based DDNS (Linux)

If no Windows workstation is available 24/7, a VPS with a static IP can run DDNS updates. This method uses a bash script with cron or systemd timer.

### Prerequisites

- Debian/Ubuntu VPS with curl and jq installed
- Cloudflare API token with Zone DNS Edit permissions

### Install Dependencies

```bash
sudo apt update && sudo apt install curl jq -y
```

### Create Script

```bash
sudo nano /usr/local/bin/cloudflare-ddns.sh
```

```bash
#!/bin/bash
# Cloudflare DDNS Update Script

set -euo pipefail

# Configuration
CF_API_TOKEN="YOUR_API_TOKEN"
ZONE_ID="YOUR_ZONE_ID"
RECORD_ID="YOUR_RECORD_ID"
RECORD_NAME="home.yourdomain.com"
TTL=300
PROXIED=false
LOG_FILE="/var/log/cloudflare-ddns.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Get current public IP
CURRENT_IP=$(curl -s https://api.ipify.org) || CURRENT_IP=$(curl -s https://ifconfig.me/ip)

if [[ -z "$CURRENT_IP" ]]; then
    log "ERROR: Failed to retrieve public IP"
    exit 1
fi

# Get current DNS IP
DNS_IP=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${RECORD_ID}" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" \
    -H "Content-Type: application/json" | jq -r '.result.content')

if [[ "$CURRENT_IP" == "$DNS_IP" ]]; then
    log "INFO: No update required ($CURRENT_IP)"
    exit 0
fi

log "INFO: IP changed from $DNS_IP to $CURRENT_IP"

# Update DNS record
RESPONSE=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${RECORD_ID}" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "{\"type\":\"A\",\"name\":\"${RECORD_NAME}\",\"content\":\"${CURRENT_IP}\",\"ttl\":${TTL},\"proxied\":${PROXIED}}")

if echo "$RESPONSE" | jq -e '.success' > /dev/null; then
    log "SUCCESS: Updated $RECORD_NAME to $CURRENT_IP"
else
    log "ERROR: Update failed - $(echo "$RESPONSE" | jq -r '.errors')"
    exit 1
fi
```

### Set Permissions

```bash
sudo chmod 700 /usr/local/bin/cloudflare-ddns.sh
sudo touch /var/log/cloudflare-ddns.log
sudo chmod 640 /var/log/cloudflare-ddns.log
```

### Option A: Cron (Every 5 Minutes)

```bash
sudo crontab -e
```

Add:

```cron
*/5 * * * * /usr/local/bin/cloudflare-ddns.sh
```

### Option B: Systemd Timer

Create service unit:

```bash
sudo nano /etc/systemd/system/cloudflare-ddns.service
```

```ini
[Unit]
Description=Cloudflare DDNS Update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/cloudflare-ddns.sh
```

Create timer unit:

```bash
sudo nano /etc/systemd/system/cloudflare-ddns.timer
```

```ini
[Unit]
Description=Run Cloudflare DDNS Update every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
AccuracySec=1min

[Install]
WantedBy=timers.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cloudflare-ddns.timer
```

### Verify

```bash
# Check timer status
systemctl list-timers | grep cloudflare

# View logs
tail -f /var/log/cloudflare-ddns.log

# Manual test
sudo /usr/local/bin/cloudflare-ddns.sh && cat /var/log/cloudflare-ddns.log
```

### VPS Consideration

If the VPS is remote from your home network, the script must query your home's public IP externally. This requires either:

1. **A device at home reports its IP to the VPS** - Home device pushes IP to VPS, VPS updates Cloudflare
2. **VPS queries a relay service** - More complex, requires additional infrastructure

For most double NAT scenarios, the Windows workstation method is simpler as it runs inside the network and can directly detect the public IP.

---

## Security Considerations

| Risk | Concern Level | Mitigation |
|------|---------------|------------|
| API token exposure | Medium | Restrict script file permissions, rotate token annually |
| IP discovery via DNS | Low | Use non-obvious subdomain, don't publish hostname |
| DNS record hijacking | Low | Requires token compromise; enable Cloudflare notifications |
| Port 1194 brute force | **None** | Certificate-based auth blocks this - no password to guess |

### Token Security

The API token is stored in plaintext in the script. To reduce risk:

- Scope token to single zone with DNS Edit only
- Set token TTL to force periodic rotation
- Restrict file permissions: `icacls "C:\Scripts\Cloudflare-DDNS.ps1" /inheritance:r /grant:r "$env:USERNAME:F"`

### OpenVPN Security

With certificate-based authentication, OpenVPN cannot be brute-forced. Without a valid client certificate, connection attempts fail immediately at the TLS handshake. The open port presents minimal attack surface.

---

## Troubleshooting

| Symptom | Cause | Resolution |
|---------|-------|------------|
| Script doesn't run | Execution policy | `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| No log entries | Directory missing | Create `C:\Scripts\Logs` |
| Task shows 0x1 | Script error | Run script manually to see error |
| DNS not updating | Invalid token | Verify token with API |
| "Access denied" | Token permissions | Ensure Zone DNS Edit permission |
| Window popup | Direct PS1 execution | Use VBS wrapper method (Part 6) |
| Garbled log text | UTF-16 encoding | Add `-Encoding UTF8` to `Out-File` in Write-Log |

### Verification Commands

```powershell
# Check public IP
Invoke-RestMethod -Uri "https://api.ipify.org"

# Check DNS resolution
nslookup home.yourdomain.com 1.1.1.1

# Verify token
Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/user/tokens/verify" -Headers @{"Authorization"="Bearer YOUR_TOKEN"}

# View recent log entries
Get-Content "C:\Scripts\Logs\cloudflare-ddns.log" -Tail 10
```

---

## UniFi Gateway DDNS

**Disable native DDNS on the UniFi gateway** when using this solution. The gateway only sees its WAN interface IP, which in double NAT is a private address. The Windows script handles DNS updates correctly by querying external services.

Once double NAT is eliminated (e.g., ISP router in bridge mode), native UniFi DDNS can be re-enabled and this script retired.

---

*Last updated: 2025-12-28*
