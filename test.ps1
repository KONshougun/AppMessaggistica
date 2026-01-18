# ---------------- CONFIG ----------------
$baseUrl = "https://tops-actually-filly.ngrok-free.app"

$utenti = @(
    @{ Username = "Giuseppe"; Password = "pwdGiuseppe123"; ID = 4 },
    @{ Username = "Paolo"; Password = "pwdPaolo123"; ID = 5 }
)

$chat = @{
    ChatId  = "6"                 # ID chat esistente
    Message = "Ciao, questo è un messaggio di test"
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

# ---------- Funzioni per utenti ----------
function SignIn-User($utente) {
    $resp = Call-Api-Timed "SIGN IN $($utente.Username)" "SignIn" @{
        Username = $utente.Username
        Password = $utente.Password
    }
    if ($resp -match '"Id":"(\d+)"') {
        $utente.ID = $matches[1]
        Write-Host "ID $($utente.Username): $($utente.ID)" -ForegroundColor Cyan
    }
}

function LogIn-User($utente) {
    $resp = Call-Api-Timed "LOG IN $($utente.Username)" "LogIn" @{
        Username = $utente.Username
        Password = $utente.Password
    }
    if ($resp -match '"Id":"(\d+)"') {
        $utente.ID = $matches[1]
        Write-Host "ID $($utente.Username) (Login): $($utente.ID)" -ForegroundColor Cyan
    }
}

function GetContacts-User($utente) {
    if (-not $utente.ID) {
        Write-Host "Impossibile ottenere contatti: ID utente mancante" -ForegroundColor Red
        return
    }
    Call-Api-Timed "GET CONTACTS $($utente.Username)" "GetContacts" @{
        Id = $utente.ID
        Password = $utente.Password
    }
}

function AddContact-User($utente, $contactUsername, $nickname) {
    if (-not $utente.ID) {
        Write-Host "Impossibile aggiungere contatto: ID utente mancante" -ForegroundColor Red
        return
    }
    Call-Api-Timed "ADD CONTACT $contactUsername to $($utente.Username)" "AddContact" @{
        Id = $utente.ID
        Password = $utente.Password
        ContactUsername = $contactUsername
        Nickname = $nickname
    }
}

function SetBlockState-User($utente, $contactUsername, $state) {
    if (-not $utente.ID) { return }
    Call-Api-Timed "SET BLOCK $contactUsername to $state" "SetBlockState" @{
        Id = $utente.ID
        Password = $utente.Password
        ContactUsername = $contactUsername
        BlockState = $state
    }
}

function SetNickname-User($utente, $contactUsername, $newNickname) {
    if (-not $utente.ID) { return }
    Call-Api-Timed "SET NICKNAME $contactUsername to $newNickname" "SetNickname" @{
        Id = $utente.ID
        Password = $utente.Password
        ContactUsername = $contactUsername
        Nickname = $newNickname
    }
}

function RemoveContact-User($utente, $contactUsername) {
    if (-not $utente.ID) { return }
    Call-Api-Timed "REMOVE CONTACT $contactUsername from $($utente.Username)" "RemoveContact" @{
        Id = $utente.ID
        Password = $utente.Password
        ContactUsername = $contactUsername
    }
}

function SendMessage($utente, $chat) {
    Call-Api-Timed "SEND MESSAGE" "SendMessage" @{
        Id       = $utente.Id
        Password = $utente.Password
        ChatId   = $chat.ChatId
        Message  = $chat.Message
    }
}

# ------------------ ESECUZIONE ------------------

# Esempio di operazioni sui contatti
SendMessage $utenti[0] $chat

Write-Host "`n=== Script utenti terminato ===" -ForegroundColor Cyan
