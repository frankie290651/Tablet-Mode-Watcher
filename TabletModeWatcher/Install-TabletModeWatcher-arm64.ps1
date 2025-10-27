param(
    [string]$PublishPath = $PSScriptRoot,
    [string]$InstallPath = (Join-Path $env:ProgramFiles "TabletModeWatcher"),
    [string]$TaskName = "TabletModeWatcher"
)

# Assicurati di eseguire in PowerShell come Administrator.

if (-not (Test-Path $PublishPath)) {
    Write-Error "PublishPath non trovato: $PublishPath"
    exit 1
}

# Se esiste una precedente installazione, fermo task e rimuovo (opzionale)
try {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Write-Host "Trovata vecchia scheduled task '$TaskName'. Provo a fermarla e a rimuoverla..."
        try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
        try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    }
} catch {
    Write-Warning "Impossibile interrogare Task Scheduler: $($_.Exception.Message)"
}

# Copia file in Program Files (richiede privilegi amministrativi)
Write-Host "Creo cartella di destinazione e copio file..."
New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
Copy-Item -Path (Join-Path $PublishPath "*") -Destination $InstallPath -Recurse -Force

# Imposta permessi di lettura/esecuzione per tutti gli utenti (opzionale)
try {
    $acl = Get-Acl $InstallPath
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users","ReadAndExecute","ContainerInherit, ObjectInherit","None","Allow")
    $acl.SetAccessRule($rule)
    Set-Acl $InstallPath $acl
} catch {
    Write-Warning "Non sono riuscito a modificare ACL su ${InstallPath}: $($_.Exception.Message)"
}

$exePath = Join-Path $InstallPath "TabletModeWatcher.exe"
if (-not (Test-Path $exePath)) {
    Write-Error "Exe non trovato in $exePath"
    exit 1
}

# Creo trigger e action
$action = New-ScheduledTaskAction -Execute $exePath
$trigger = New-ScheduledTaskTrigger -AtLogOn

# Settings: proviamo a creare settings compatibili, senza usare MultipleInstancesPolicy
try {
    # -Hidden è opzionale e potrebbe non essere supportato in alcune versioni del modulo, ma ci proviamo
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -Hidden
} catch {
    Write-Warning "New-ScheduledTaskSettingsSet con -Hidden non è supportato: $($_.Exception.Message). Procedo senza settings avanzati."
    $settings = $null
}

# Registriamo la task per l'utente corrente con RunLevel Highest (richiede PowerShell eseguita come Admin)
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

try {
    if ($settings -ne $null) {
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force
    } else {
        # Se non possiamo usare Settings oggettuali, proviamo comunque a registrare con i soli Action/Trigger/Principal
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force
    }
    Write-Host "Scheduled Task '$TaskName' creata con Register-ScheduledTask."
} catch {
    Write-Warning "Register-ScheduledTask ha fallito: $($_.Exception.Message). Provo con schtasks.exe come fallback..."
    $exePathEsc = '"' + $exePath + '"'
    schtasks /Create /TN $TaskName /TR $exePathEsc /SC ONLOGON /RL HIGHEST /F
    Write-Host "Scheduled Task creata via schtasks (fallback)."
}

Write-Host "Installazione completata. Controlla Task Scheduler e il file di log %ProgramData%\TabletModeWatcher\watcher.log"