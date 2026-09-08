<#
.SYNOPSIS
    Auditoria de controles de segurança em endpoint Windows — pré-checagem
    para uso em engajamento de pentest interno.

.DESCRIPTION
    Coleta o estado de: BitLocker, EDR (CrowdStrike Falcon / Defender / outros),
    Windows Firewall, UAC, SMBv1, RDP, Execution Policy do PowerShell, LSA
    Protection, Credential Guard, Windows Update, contas locais com privilégio
    admin, e serviços críticos.

    Não altera nenhuma configuração — apenas leitura/relatório.

.NOTES
    Execute como Administrador para resultados completos (WMI/registro
    exigem elevação em vários pontos).

.EXAMPLE
    .\Check-SecurityControls.ps1
    .\Check-SecurityControls.ps1 -ExportPath C:\Temp\report.json
#>

[CmdletBinding()]
param(
    [string]$ExportPath
)

$ErrorActionPreference = 'SilentlyContinue'
$results = [ordered]@{}

function Write-Section($title) {
    Write-Host "`n=== $title ===" -ForegroundColor Cyan
}

function Add-Result($category, $key, $value, $status = 'INFO') {
    if (-not $results.Contains($category)) { $results[$category] = [ordered]@{} }
    $results[$category][$key] = @{ Value = $value; Status = $status }
    $color = switch ($status) {
        'OK'   { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
        default { 'Gray' }
    }
    Write-Host ("  {0,-40}: {1}" -f $key, $value) -ForegroundColor $color
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Executando como Administrador: $isAdmin" -ForegroundColor $(if ($isAdmin) {'Green'} else {'Yellow'})
if (-not $isAdmin) {
    Write-Host "AVISO: alguns checks podem retornar dados incompletos sem elevação." -ForegroundColor Yellow
}

# ----------------------------------------------------------------------
Write-Section "Informações do Sistema"
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
Add-Result 'System' 'Hostname'      $env:COMPUTERNAME
Add-Result 'System' 'Domain/Workgroup' $cs.Domain
Add-Result 'System' 'OS'            "$($os.Caption) $($os.Version)"
Add-Result 'System' 'Build'         $os.BuildNumber
Add-Result 'System' 'InstallDate'   $os.InstallDate

# ----------------------------------------------------------------------
Write-Section "BitLocker"
$blModuleOk = $false
try {
    $bl = Get-BitLockerVolume -ErrorAction Stop
    $blModuleOk = $true
    foreach ($vol in $bl) {
        $status = if ($vol.ProtectionStatus -eq 'On') { 'OK' } else { 'FAIL' }
        Add-Result 'BitLocker' "Volume $($vol.MountPoint)" "Protection=$($vol.ProtectionStatus) | Encryption=$($vol.EncryptionPercentage)% | Method=$($vol.EncryptionMethod)" $status

        # Detalha os key protectors (TPM, Recovery Password, Password, etc.)
        # Independe de como o BitLocker foi habilitado (manual, GPO, Intune/MDM) —
        # o estado é sempre lido do WMI local, não da origem do enrollment.
        foreach ($kp in $vol.KeyProtector) {
            Add-Result 'BitLocker' "  KeyProtector [$($vol.MountPoint)]" "$($kp.KeyProtectorType) | ID=$($kp.KeyProtectorId)" 'INFO'
        }
        if ('RecoveryPassword' -notin $vol.KeyProtector.KeyProtectorType) {
            Add-Result 'BitLocker' "  Recovery Key presente [$($vol.MountPoint)]" 'NÃO ENCONTRADA' 'WARN'
        }
    }
} catch {
    Add-Result 'BitLocker' 'Módulo PowerShell BitLocker' 'Indisponível (checando via manage-bde)' 'WARN'
}

# Fallback nativo — funciona em qualquer edição do Windows (Pro/Enterprise/Education/Home
# com IU limitada) e não depende do módulo PowerShell nem de como o BitLocker foi ativado.
if (-not $blModuleOk) {
    try {
        $mbde = manage-bde -status 2>$null
        if ($mbde) {
            $mbde | ForEach-Object {
                if ($_ -match 'Volume|Protection Status|Percentage Encrypted|Encryption Method|Lock Status') {
                    Add-Result 'BitLocker' 'manage-bde output' $_.Trim() 'INFO'
                }
            }
        } else {
            Add-Result 'BitLocker' 'manage-bde' 'Binário não retornou dados (verifique elevação)' 'WARN'
        }
    } catch {
        Add-Result 'BitLocker' 'manage-bde' 'Não disponível neste SO' 'WARN'
    }
}

# ----------------------------------------------------------------------
Write-Section "EDR / Antivírus"
# CrowdStrike Falcon
$csSvc = Get-Service -Name CSFalconService -ErrorAction SilentlyContinue
if ($csSvc) {
    Add-Result 'EDR' 'CrowdStrike Falcon Service' "$($csSvc.Status)" $(if ($csSvc.Status -eq 'Running') {'OK'} else {'FAIL'})
    $csPath = "$env:SystemRoot\System32\drivers\CrowdStrike"
    if (Test-Path $csPath) {
        Add-Result 'EDR' 'CrowdStrike Driver Path' 'Presente' 'OK'
    }
    try {
        $csReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim' -ErrorAction SilentlyContinue
        if ($csReg.AG) { Add-Result 'EDR' 'CrowdStrike AgentID (AG)' 'Presente' 'INFO' }
    } catch {}
} else {
    Add-Result 'EDR' 'CrowdStrike Falcon Service' 'Não encontrado' 'WARN'
}

# Windows Defender
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    Add-Result 'EDR' 'Defender AMServiceEnabled'   $mp.AMServiceEnabled  $(if ($mp.AMServiceEnabled) {'OK'} else {'WARN'})
    Add-Result 'EDR' 'Defender RealTimeProtection' $mp.RealTimeProtectionEnabled $(if ($mp.RealTimeProtectionEnabled) {'OK'} else {'WARN'})
    Add-Result 'EDR' 'Defender AntivirusEnabled'   $mp.AntivirusEnabled $(if ($mp.AntivirusEnabled) {'OK'} else {'WARN'})
    Add-Result 'EDR' 'Defender AV Signature Age (dias)' $mp.AntivirusSignatureAge $(if ($mp.AntivirusSignatureAge -le 3) {'OK'} else {'WARN'})
    Add-Result 'EDR' 'Defender Tamper Protection' $mp.IsTamperProtected $(if ($mp.IsTamperProtected) {'OK'} else {'WARN'})
} catch {
    Add-Result 'EDR' 'Windows Defender' 'Cmdlet não disponível (possivelmente substituído por AV terceiro)' 'INFO'
}

# Produto AV registrado no Security Center
try {
    $avList = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
    foreach ($av in $avList) {
        Add-Result 'EDR' "AV registrado (SecurityCenter2)" "$($av.displayName)" 'INFO'
    }
} catch {
    Add-Result 'EDR' 'SecurityCenter2' 'Não foi possível consultar' 'WARN'
}

# ----------------------------------------------------------------------
Write-Section "Firewall"
try {
    $fw = Get-NetFirewallProfile
    foreach ($p in $fw) {
        Add-Result 'Firewall' "$($p.Name) Profile Enabled" $p.Enabled $(if ($p.Enabled) {'OK'} else {'FAIL'})
    }
} catch {
    Add-Result 'Firewall' 'Status' 'Não foi possível consultar Get-NetFirewallProfile' 'WARN'
}

# ----------------------------------------------------------------------
Write-Section "UAC (User Account Control)"
$uacKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$uacEnabled = (Get-ItemProperty -Path $uacKey -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
$uacLevel   = (Get-ItemProperty -Path $uacKey -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
Add-Result 'UAC' 'EnableLUA' $uacEnabled $(if ($uacEnabled -eq 1) {'OK'} else {'FAIL'})
Add-Result 'UAC' 'ConsentPromptBehaviorAdmin' $uacLevel 'INFO'

# ----------------------------------------------------------------------
Write-Section "SMBv1"
try {
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    Add-Result 'SMB' 'SMBv1 Feature State' $smb1.State $(if ($smb1.State -eq 'Disabled') {'OK'} else {'FAIL'})
} catch {
    Add-Result 'SMB' 'SMBv1' 'Não foi possível consultar (Server Core / Home?)' 'WARN'
}

# ----------------------------------------------------------------------
Write-Section "RDP (Remote Desktop)"
$rdpDeny = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
Add-Result 'RDP' 'fDenyTSConnections (1=RDP desabilitado)' $rdpDeny $(if ($rdpDeny -eq 1) {'OK'} else {'WARN'})
$nla = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
Add-Result 'RDP' 'Network Level Authentication (NLA)' $nla $(if ($nla -eq 1) {'OK'} else {'WARN'})

# ----------------------------------------------------------------------
Write-Section "PowerShell — Execution Policy / Logging / CLM"
Add-Result 'PowerShell' 'ExecutionPolicy (LocalMachine)' (Get-ExecutionPolicy -Scope LocalMachine)
Add-Result 'PowerShell' 'ExecutionPolicy (CurrentUser)'  (Get-ExecutionPolicy -Scope CurrentUser)
$psVersion = $PSVersionTable.PSVersion.ToString()
Add-Result 'PowerShell' 'Versão' $psVersion

$scriptBlockLog = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
Add-Result 'PowerShell' 'ScriptBlockLogging Habilitado' $scriptBlockLog $(if ($scriptBlockLog -eq 1) {'OK'} else {'WARN'})

$moduleLog = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name EnableModuleLogging -ErrorAction SilentlyContinue).EnableModuleLogging
Add-Result 'PowerShell' 'ModuleLogging Habilitado' $moduleLog $(if ($moduleLog -eq 1) {'OK'} else {'WARN'})

$transcription = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name EnableTranscripting -ErrorAction SilentlyContinue).EnableTranscripting
Add-Result 'PowerShell' 'Transcription Habilitada' $transcription 'INFO'

# Indício de CLM (Constrained Language Mode) ativo na sessão atual
Add-Result 'PowerShell' 'LanguageMode (sessão atual)' $ExecutionContext.SessionState.LanguageMode 'INFO'

# ----------------------------------------------------------------------
Write-Section "LSA Protection / Credential Guard"
$lsaProt = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
Add-Result 'LSA' 'RunAsPPL (LSA Protection)' $lsaProt $(if ($lsaProt -eq 1) {'OK'} else {'WARN'})

try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    Add-Result 'LSA' 'Credential Guard (SecurityServicesRunning)' ($dg.SecurityServicesRunning -join ',') 'INFO'
} catch {
    Add-Result 'LSA' 'Credential Guard' 'Não foi possível consultar' 'INFO'
}

# ----------------------------------------------------------------------
Write-Section "Windows Update"
try {
    $auto = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -ErrorAction SilentlyContinue).AUOptions
    Add-Result 'WindowsUpdate' 'AUOptions' $auto 'INFO'
} catch {}
$hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
foreach ($hf in $hotfixes) {
    Add-Result 'WindowsUpdate' "KB recente" "$($hf.HotFixID) - $($hf.InstalledOn)" 'INFO'
}

# ----------------------------------------------------------------------
Write-Section "Contas Locais e Administradores"
try {
    $admins = Get-LocalGroupMember -Group 'Administradores' -ErrorAction SilentlyContinue
    if (-not $admins) { $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue }
    foreach ($a in $admins) {
        Add-Result 'LocalAccounts' 'Membro do grupo Administradores' $a.Name 'WARN'
    }
} catch {
    Add-Result 'LocalAccounts' 'Grupo Administradores' 'Não foi possível enumerar' 'WARN'
}

$guestEnabled = (Get-LocalUser -Name 'Convidado' -ErrorAction SilentlyContinue).Enabled
if ($null -eq $guestEnabled) { $guestEnabled = (Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled }
Add-Result 'LocalAccounts' 'Conta Guest Habilitada' $guestEnabled $(if ($guestEnabled -eq $false) {'OK'} else {'FAIL'})

# ----------------------------------------------------------------------
Write-Section "Serviços Críticos de Segurança"
$criticalServices = @('WinDefend','wuauserv','EventLog','MpsSvc','SecurityHealthService','Sense')
foreach ($svcName in $criticalServices) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc) {
        Add-Result 'Services' "$svcName" $svc.Status $(if ($svc.Status -eq 'Running') {'OK'} else {'WARN'})
    }
}

# ----------------------------------------------------------------------
Write-Section "TPM"
try {
    $tpm = Get-Tpm -ErrorAction Stop
    Add-Result 'TPM' 'Present' $tpm.TpmPresent 'INFO'
    Add-Result 'TPM' 'Ready'   $tpm.TpmReady   $(if ($tpm.TpmReady) {'OK'} else {'WARN'})
} catch {
    Add-Result 'TPM' 'Status' 'Módulo Get-Tpm indisponível' 'WARN'
}

# ----------------------------------------------------------------------
Write-Section "Resumo"
$fails = 0; $warns = 0
foreach ($cat in $results.Keys) {
    foreach ($k in $results[$cat].Keys) {
        switch ($results[$cat][$k].Status) {
            'FAIL' { $fails++ }
            'WARN' { $warns++ }
        }
    }
}
Write-Host "Itens em FAIL : $fails" -ForegroundColor Red
Write-Host "Itens em WARN : $warns" -ForegroundColor Yellow

if ($ExportPath) {
    $results | ConvertTo-Json -Depth 6 | Out-File -FilePath $ExportPath -Encoding UTF8
    Write-Host "`nRelatório exportado para: $ExportPath" -ForegroundColor Cyan
}