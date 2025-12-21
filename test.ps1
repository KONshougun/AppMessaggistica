# ---------------- CONFIG ----------------
$ngrokBase = "https://tops-actually-filly.ngrok-free.app"

# Utente da testare
$user = @{ Username = "Giuseppe"; Password = "pwdGiuseppe123" }

# ---------- helper: chiamata API ----------
function Call-Api {
    param($path, $bodyMap)
    $uri = "$ngrokBase/$path"
    try {
        $resp = Invoke-WebRequest -Uri $uri -Method POST -Body $bodyMap -ContentType "application/x-www-form-urlencoded" -UseBasicParsing -ErrorAction Stop
        return $resp.Content
    } catch {
        Write-Host "ERRORE HTTP -> $uri" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        return $null
    }
}

# ------------------ ESECUZIONE ------------------

Write-Host "`n>>> Effettuo SignIn per $($user.Username)" -ForegroundColor Cyan
$response = Call-Api "SignIn" @{ Username = $user.Username; Password = $user.Password }

if ($null -eq $response) {
    Write-Host "Nessuna risposta dal server" -ForegroundColor Red
} else {
    Write-Host "Risposta server:`n$response" -ForegroundColor Green
}

Write-Host "`n=== Script terminato ==="
