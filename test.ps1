# ---------------- CONFIG ----------------
$baseUrl = "https://tops-actually-filly.ngrok-free.app"

# Utente principale (deve aver effettuato SignIn o LogIn)
$user = @{
    ID = "2"            # ID ottenuto dal SignIn/LogIn
    Password = "pwdGiuseppe123"
}

# Contatto da aggiungere
$contact = @{
    Username = "Paolo"       # Username del contatto
    Nickname = "Amico Paolo" # Nickname da assegnare
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

Write-Host "`n>>> Aggiungo contatto $($contact.Username) all'utente ID $($user.ID)" -ForegroundColor Cyan

$addResp = Call-Api "AddContact" @{
    ID = $user.ID
    Password = $user.Password
    ContactUsername = $contact.Username
    Nickname = $contact.Nickname
}

if ($null -eq $addResp) {
    Write-Host "Nessuna risposta dal server" -ForegroundColor Red
} else {
    Write-Host "Risposta server:" -ForegroundColor Green
    Write-Host $addResp
}

Write-Host "`n=== Script terminato ==="
