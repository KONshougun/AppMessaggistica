# ---------------- CONFIG ----------------
$baseUrl = "https://tops-actually-filly.ngrok-free.app"

$giuseppe = @{
    Username = "Giuseppe"
    Password = "pwdGiuseppe123"
    ID       = "2"  # Inserire ID corretto dopo SignIn/LogIn
}

$paolo = @{
    Username    = "Paolo"
    Nickname    = "Amico Paolo"
    NewNickname = "Paolo Fidato"
}

# ---------- helper HTTP + timing ----------
function Call-Api-Timed {
    param(
        [string]$label,
        [string]$path,
        [hashtable]$body
    )

    Write-Host "`n>>> $label" -ForegroundColor Cyan
    $uri = "$baseUrl/$path"

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $resp = Invoke-WebRequest `
            -Uri $uri `
            -Method POST `
            -Body $body `
            -ContentType "application/x-www-form-urlencoded" `
            -UseBasicParsing `
            -ErrorAction Stop

        $sw.Stop()
        Write-Host "Tempo risposta: $($sw.Elapsed.TotalMilliseconds) ms" -ForegroundColor Yellow
        Write-Host "Risposta server:" -ForegroundColor Green
        Write-Host $resp.Content
        return $resp.Content
    }
    catch {
        $sw.Stop()
        Write-Host "Tempo risposta (ERRORE): $($sw.Elapsed.TotalMilliseconds) ms" -ForegroundColor Yellow
        Write-Host "ERRORE HTTP -> $uri" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        return $null
    }
}

# ------------------ ESECUZIONE ------------------

# 1) LOGIN Giuseppe
Call-Api-Timed "LOGIN Giuseppe" "LogIn" @{
    Username = $giuseppe.Username
    Password = $giuseppe.Password
}

# 2) ADD CONTACT Paolo
Call-Api-Timed "ADD CONTACT Paolo" "AddContact" @{
    ID              = $giuseppe.ID
    Password        = $giuseppe.Password
    ContactUsername = $paolo.Username
    Nickname        = $paolo.Nickname
}

# 3) GET CONTACTS Giuseppe
Call-Api-Timed "GET CONTACTS Giuseppe" "GetContacts" @{
    ID       = $giuseppe.ID
    Password = $giuseppe.Password
}

# 4) SET NICKNAME Paolo
Call-Api-Timed "SET NICKNAME Paolo" "SetNickname" @{
    ID              = $giuseppe.ID
    Password        = $giuseppe.Password
    ContactUsername = $paolo.Username
    Nickname        = $paolo.NewNickname
}

Write-Host "`n=== Script terminato ===" -ForegroundColor Cyan
