# ---------------- CONFIG ----------------
$baseUrl = "https://tops-actually-filly.ngrok-free.app"

# Utente autenticato
$user = @{
    ID       = "2"                 # ID ottenuto da SignIn / LogIn
    Password = "pwdGiuseppe123"
}

# Contatto da rimuovere
$contact = @{
    Username = "Paolo"             # username del contatto da rimuovere
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

Write-Host "`n>>> Rimuovo contatto '$($contact.Username)'" -ForegroundColor Cyan

$response = Call-Api "RemoveContact" @{
    ID              = $user.ID
    Password        = $user.Password
    ContactUsername = $contact.Username
}

if ($null -eq $response -or $response.Trim() -eq "") {
    Write-Host "Nessuna risposta dal server (possibile OK silenzioso)" -ForegroundColor Yellow
} else {
    Write-Host "Risposta server:" -ForegroundColor Green
    Write-Host $response
}

Write-Host "`n=== Script terminato ==="
