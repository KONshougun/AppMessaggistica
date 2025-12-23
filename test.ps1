# ---------------- CONFIG ----------------
$baseUrl = "https://tops-actually-filly.ngrok-free.app"

# Utente autenticato
$user = @{
    ID       = "2"                 # ID ottenuto da SignIn / LogIn
    Password = "pwdGiuseppe123"    # Password in chiaro (come richiesto dal server)
}

# ---------- helper HTTP ----------
function Call-Api {
    param(
        [string]$path,
        [hashtable]$body
    )

    $uri = "$baseUrl/$path"

    try {
        $resp = Invoke-WebRequest `
            -Uri $uri `
            -Method POST `
            -Body $body `
            -ContentType "application/x-www-form-urlencoded" `
            -UseBasicParsing `
            -ErrorAction Stop

        return $resp.Content
    }
    catch {
        Write-Host "ERRORE HTTP -> $uri" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        return $null
    }
}

# ------------------ ESECUZIONE ------------------

Write-Host "`n>>> Richiamo GetContacts per utente ID $($user.ID)" -ForegroundColor Cyan

$response = Call-Api "GetContacts" @{
    ID       = $user.ID
    Password = $user.Password
}

if ($null -eq $response) {
    Write-Host "Nessuna risposta dal server" -ForegroundColor Red
} else {
    Write-Host "Risposta server:" -ForegroundColor Green
    Write-Host $response
}

Write-Host "`n=== Script terminato ==="
