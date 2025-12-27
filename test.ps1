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

$chat = @{
    ChatId  = "3"
    Message = "Ciao Paolo, come va?"
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

# 5) SEND MESSAGE nella chat
Call-Api-Timed "SEND MESSAGE Chat" "SendMessage" @{
    Id       = $giuseppe.ID
    Password = $giuseppe.Password
    ChatId   = $chat.ChatId
    Message  = $chat.Message
}

Write-Host "`n=== Script terminato ===" -ForegroundColor Cyan
