# Master Crypto Lab v8.1 — Guida dettagliata all’utilizzo

Questa guida descrive l’installazione, il flusso operativo completo e l’uso di ogni area dell’interfaccia. È pensata per un utente che apre l’applicazione per la prima volta fino a produrre un **evidence pack** presentabile.

---

## Indice

1. [Requisiti e installazione](#1-requisiti-e-installazione)
2. [Avvio dell’applicazione](#2-avvio-dellapplicazione)
3. [Panoramica interfaccia](#3-panoramica-interfaccia)
4. [Workflow consigliato (4 stadi)](#4-workflow-consigliato-4-stadi)
5. [Sidebar — KEY OPS](#5-sidebar--key-ops)
6. [Tab 01 — ENCRYPT](#6-tab-01--encrypt)
7. [Tab 02 — DECRYPT](#7-tab-02--decrypt)
8. [Tab 03 — STEGO](#8-tab-03--stego)
9. [Tab 04 — NIST LAB](#9-tab-04--nist-lab)
10. [Tab 05 — ML CORE](#10-tab-05--ml-core)
11. [Tab 06 — HISTORY](#11-tab-06--history)
12. [Tab 07 — ENTERPRISE](#12-tab-07--enterprise)
13. [Email split-channel (chiave e ciphertext)](#13-email-split-channel-chiave-e-ciphertext)
14. [Preset demo e tour guidato](#14-preset-demo-e-tour-guidato)
15. [API locale (opzionale)](#15-api-locale-opzionale)
16. [Problemi comuni](#16-problemi-comuni)
17. [Checklist demo da 5 minuti](#17-checklist-demo-da-5-minuti)

---

## 1. Requisiti e installazione

### 1.1 Software necessario

- **Python 3.10+** (consigliato 3.11 o 3.12)
- pip aggiornato
- (Windows) eventuale “App execution aliases” disattivati se `python` non risolve correttamente

### 1.2 Installazione dipendenze

Dalla cartella del progetto (`Progetto_CRIPTOGRAFIA_AVANZATA`):

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt
```

**Opzionali consigliati:**

```bash
pip install argon2-cffi      # Argon2id in sidebar
pip install reportlab         # Report PDF in tab Enterprise
pip install fastapi uvicorn   # API locale
```

### 1.3 Struttura minima attesa

```
Progetto_CRIPTOGRAFIA_AVANZATA/
├── Cryptography.py          # entry point Streamlit
├── requirements.txt
├── cipher_classifier.joblib # modello ML (si ricrea se assente)
├── crypto_history.csv       # history (creato all’uso)
├── crypto_lab/              # motore
├── SINOPSI.md
└── GUIDA_UTILIZZO.md
```

---

## 2. Avvio dell’applicazione

```bash
cd Progetto_CRIPTOGRAFIA_AVANZATA
streamlit run Cryptography.py
```

Su Windows è disponibile anche `run.bat` (se configurato per lanciare lo stesso comando).

Il browser si apre in genere su `http://localhost:8501`.

Al primo avvio può comparire:

- **boot sequence** a schermo intero (pochi secondi);
- **addestramento ML** se manca `cipher_classifier.joblib` (attendi lo spinner).

---

## 3. Panoramica interfaccia

### 3.1 Header console

Mostra il titolo **MASTER CRYPTO LAB** e chip di stato:

| Chip | Significato |
|------|-------------|
| **SYSTEM ARMED** | Chiave attiva in sessione |
| **AWAITING KEY** | Nessuna chiave: va generata/derivata |
| **ML ONLINE** | Classificatore caricato e addestrato |

### 3.2 Barra workflow

Quattro stadi:

1. **KEY** — chiave presente  
2. **ENCRYPT** — esiste un ciphertext in sessione  
3. **ANALYZE** — metriche NIST/cache compilate  
4. **EXPORT** — è stato generato almeno un export (evidence pack)

Gli stadi completati appaiono evidenziati (stile “done”).

### 3.3 Sidebar (sinistra)

Contiene sempre le operazioni su **cipher**, **derivazione chiave**, (con chiave attiva) **QR**, **pesi metriche**, **SECURE MAIL**.

> Se la sidebar non è visibile: usa il controllo freccia/hamburger sul bordo sinistro della pagina Streamlit.

### 3.4 Area principale — 7 tab

| Tab | Funzione |
|-----|----------|
| **01 ENCRYPT** | Cifratura, license code, pipeline, padding/IV |
| **02 DECRYPT** | Decifratura manuale (mode + chiave + ciphertext) |
| **03 STEGO** | Nascondere/estrarre ciphertext in immagine LSB |
| **04 NIST LAB** | Grafici e test statistici sul ciphertext |
| **05 ML CORE** | Classificazione mode, anomaly, explainability |
| **06 HISTORY** | Dataset storico delle cifratura |
| **07 ENTERPRISE** | Compliance, benchmark, export, case file, PQC |

---

## 4. Workflow consigliato (4 stadi)

### Scenario standard “cipher forte”

1. Sidebar → **Cipher Mode** = `AES-256-GCM` (o ChaCha20-Poly1305).  
2. **Key Generation Method** = `Random Key` → **Generate Random Key**.  
3. Verifica chip **SYSTEM ARMED**.  
4. Tab **01 ENCRYPT** → inserisci testo → **Encrypt**.  
5. Tab **04 NIST LAB** → leggi radar, p-value, heatmap, avalanche.  
6. Tab **05 ML CORE** → verifica predizione e contribution.  
7. Tab **07 ENTERPRISE** → compliance score → **Build evidence pack**.

### Scenario “confronto debole vs forte”

1. Usa preset **Weak classical (Vigenère)** (vedi §14), cifra, osserva NIST/ML.  
2. Poi preset **Corporate AEAD (AES-256-GCM)** e confronta entropy e p-value.

---

## 5. Sidebar — KEY OPS

### 5.1 Demo presets

Espandi **Demo presets**:

1. Scegli uno scenario (es. *Corporate AEAD*).  
2. Clicca **APPLY PRESET**.  
3. Il cipher mode e il plaintext di esempio vengono preparati; genera comunque la chiave e cifra in Tab 01.

### 5.2 Guided tour

Espandi **Guided tour (5 min)** per la scaletta riassuntiva dei tab.

### 5.3 Cipher Mode

Menu a tendina con tutte le modalità registrate.  
Sotto compare la **description** tecnica.  
I mode **educational** mostrano un warning: non usarli come se fossero sicuri in produzione.

### 5.4 Key Generation Method

| Metodo | Cosa serve in UI |
|--------|------------------|
| Random Key | Solo bottone genera |
| PBKDF2 / scrypt / Argon2id / Layered | Passphrase (+ meter di forza) |
| HKDF / HMAC seed / SHA-256 direct | Materiale/seed aggiuntivo |
| ECDH X25519 | Chiave pubblica peer (Base64) |

Dopo generazione/derivazione:

- compare il banner **SYSTEM ARMED**;
- puoi mostrare la chiave (checkbox), generare **QR Code** (se installato `qrcode`);
- compaiono gli slider **METRIC WEIGHTS** (pesi del Security Index);
- compare la sezione **SECURE MAIL** (§13).

### 5.5 Note su Argon2id

Se manca `argon2-cffi`, la derivazione fallisce con messaggio esplicito: installa il pacchetto e riprova.

---

## 6. Tab 01 — ENCRYPT

### 6.1 Procedura

1. Assicurati che la chiave sia attiva (sidebar).  
2. Inserisci o modifica il **Plaintext Input**.  
3. Clicca **Encrypt**.

### 6.2 Output tipici

- **License Code** — stringa derivata dal ciphertext (uso dimostrativo/etichetta).  
- **Ciphertext** — in Base64 o Hex a seconda del mode.  
- **Cipher pipeline** — sequenza narrativa del mode (es. Plaintext → Key+Nonce → AEAD → Tag → CT).  
- **Ciphertext anatomy** — breakdown IV/nonce, payload, MAC/tag con offset.  
- **PKCS#7 padding visualization** — utile sui mode a blocchi.  
- **IV / Nonce structure** — lunghezze e warning (es. riuso nonce su GCM).

I risultati analitici vengono anche scritti in **history** e in `metrics_cache` per i tab successivi.

### 6.3 Errori frequenti

| Messaggio | Causa / azione |
|-----------|----------------|
| Generate or derive a key… | Nessuna chiave in sessione |
| Encryption failed | Chiave incompatibile col mode (rigenera dopo aver cambiato cipher) |

---

## 7. Tab 02 — DECRYPT

1. Seleziona lo **stesso Cipher Mode** usato in cifratura.  
2. Incolla la **chiave** nel formato atteso (Fernet string / hex / PEM per RSA-hybrid).  
3. Incolla il **ciphertext** (Base64 o hex coerente col mode).  
4. **Decrypt**.

In caso di HMAC/tag non validi compare errore di autenticazione: il ciphertext potrebbe essere stato alterato o la chiave è sbagliata.

---

## 8. Tab 03 — STEGO

Flusso tipico:

1. Cifra prima un messaggio (Tab 01) oppure prepara ciphertext e chiave.  
2. Carica un’**immagine cover**.  
3. Nascondi il ciphertext (LSB).  
4. Scarica l’immagine stego.  
5. In un secondo momento: carica stego + chiave + mode → **extract & decrypt**.

**Limiti:** capacità dipendente dalla risoluzione; immagini troppo piccole non bastano per payload lunghi. Preferire PNG rispetto a JPEG (il JPEG lossy può distruggere i bit LSB).

---

## 9. Tab 04 — NIST LAB

Richiede un ciphertext già prodotto in Tab 01 (`metrics_cache` valorizzata).

### 9.1 Cosa osservare

| Elemento | Lettura operativa |
|----------|-------------------|
| **Security Index** | Indice composito 0–1 (pesi dalla sidebar) |
| **Radar metriche** | Vicinanza all’ideale (entropia, SAC, uniformity, …) |
| **p-value NIST** | PASS se ≥ 0.01 (α configurata concettualmente a 0.01) |
| **p-value radar** | Panoramica multi-test |
| **Bitstream heatmap** | Struttura visiva del ciphertext |
| **Avalanche** | % bit cambiati dopo flip di 1 bit del plaintext (~50% ideale) |
| **Rolling entropy** | Stabilità dell’entropia lungo il flusso |
| **FFT** | Picchi vs soglia NIST (struttura periodica residua) |
| **Runs / byte histogram** | Deviazioni dalla casualità attesa |

### 9.2 Interpretazione rapida

- Cipher **AEAD moderni** su testo sufficiente: entropy alta, p-value spesso oltre soglia, avalanche vicino al 50%.  
- Cipher **educativi** (Vigenère, XOR debole): entropy più bassa, test che falliscono, utile in demo “cosa non va”.

---

## 10. Tab 05 — ML CORE

Richiede metriche da una cifratura recente.

### 10.1 Classificazione

- **Predicted Cipher** + confidence  
- Top-3 probabilità  
- Grafico distribuzione classi  

### 10.2 Explainability

Sezione **Why this prediction?** — barre delle feature che pesano di più (proxy importance × |valore|). Serve a spiegare *perché* il modello inclina verso una classe, non come prova crittografica formale.

### 10.3 Anomaly detection

**Isolation Forest**: score e flag ANOMALY/Normal. Mode fuori dalle 10 classi di training tendono a risultare anomali.

### 10.4 Altri strumenti

- Feature importance (permutation)  
- PCA / t-SNE su history (servono abbastanza entry)  
- Confusion matrix e learning curve (on-demand)  
- **Retrain with history** (almeno ~5 campioni in history)

### 10.5 Model card

La scheda modello completa è anche in **Tab 07**; in Tab 05 l’enfasi è sull’inferenza della sessione corrente.

---

## 11. Tab 06 — HISTORY

- Tabella di tutte le cifratura registrate (metriche + mode + security index).  
- **Download CSV** del dataset.  
- **Clear History** per azzerare (irreversibile lato file locale).

La history alimenta PCA/t-SNE e il retrain ML.

---

## 12. Tab 07 — ENTERPRISE

### 12.1 Compliance checklist

Elenco controlli **C01–C08** (chiave presente, mode non educational, AEAD/HMAC, KDF, monobit, FFT, entropy, policy canali).  
Lo **score %** riassume i PASS.

### 12.2 Evidence export

1. (Opzionale) inserisci **Case notes**.  
2. **Build evidence pack (ZIP)** → download.  
3. Contenuto tipico dello ZIP:
   - `report.txt`
   - `metrics.json`
   - `compliance.json`
   - `session_meta.json`
   - `ciphertext.bin` / `ciphertext.hex.txt` (se disponibile)
   - `benchmark.json` (se hai eseguito il benchmark)

4. **PDF report** se `reportlab` è installato; altrimenti **text report**.

Completare un export aggiorna lo stadio workflow **EXPORT**.

### 12.3 Case file collaborativo

- **Export case file (JSON)** — condivide mode, metriche, preview plaintext, hex ciphertext, note; **non** include la chiave raw.  
- **Import** — ricarica un case per review (visualizzazione JSON).

### 12.4 Multi-cipher benchmark

1. Imposta un plaintext di prova.  
2. **Run benchmark**.  
3. Tabella: tempo encrypt/decrypt, entropy, monobit p, round-trip OK.  
4. Grafico entropy per mode.

Utile per slide comparative “stesso messaggio, algoritmi diversi”.

### 12.5 Model card e API

- JSON del model card (task, limiti, accuracy).  
- Hint per avviare l’API locale (§15).

### 12.6 Post-quantum lab (educativo)

- Tabella algoritmi NIST (ML-KEM, ML-DSA, SLH-DSA, …).  
- Migration checklist.  
- **Toy KEM demo** — solo didattica: **non sicuro**, non usare in sistemi reali.

---

## 13. Email split-channel (chiave e ciphertext)

Disponibile in sidebar quando la chiave è attiva.

### 13.1 Configurazione SMTP

Espandi **SMTP Configuration**:

- Oppure variabili d’ambiente: `SMTP_SERVER`, `SMTP_PORT`, `SMTP_EMAIL`, `SMTP_PASSWORD`  
- Oppure campi manuali (server, porta, mittente, app password)

**Gmail:** usare una **App Password**, non la password dell’account.

### 13.2 Canale ① — Send KEY

- Destinatario dedicato alla **chiave**.  
- Invia solo materiale di chiave + cipher mode.

### 13.3 Canale ② — Send CIPHERTEXT

- Destinatario dedicato al **ciphertext** (può essere diverso).  
- Non include la chiave.

**Buona pratica demo:** due destinatari diversi, o due invii separati anche allo stesso indirizzo, sottolineando il principio *split-channel*.

---

## 14. Preset demo e tour guidato

| Preset | Obiettivo didattico |
|--------|---------------------|
| Corporate AEAD (AES-256-GCM) | Baseline moderna autenticata |
| Modern stream (ChaCha20-Poly1305) | AEAD ad alte prestazioni |
| Weak classical (Vigenère) | Fallimenti statistici evidenti |
| Hybrid envelope (RSA+AES) | Pattern reale “wrap + AEAD” |

Dopo **APPLY PRESET**, genera la chiave e lancia **Encrypt**: il testo di esempio è già predisposto.

---

## 15. API locale (opzionale)

```bash
pip install fastapi uvicorn
cd Progetto_CRIPTOGRAFIA_AVANZATA
uvicorn crypto_lab.api_server:app --host 127.0.0.1 --port 8765
```

Endpoint principali:

| Metodo | Path | Uso |
|--------|------|-----|
| GET | `/health` | Stato e conteggio cipher |
| GET | `/ciphers` | Elenco mode |
| POST | `/encrypt` | `mode`, `key_hex`, `plaintext` |
| POST | `/decrypt` | `mode`, `key_hex`, `ciphertext_hex` |
| POST | `/metrics` | Metriche su ciphertext hex |
| POST | `/benchmark` | Benchmark multi-mode |

Documentazione interattiva: `http://127.0.0.1:8765/docs`

Esporre solo su localhost in contesti non controllati.

---

## 16. Problemi comuni

| Sintomo | Soluzione |
|---------|-----------|
| `ModuleNotFoundError: qrcode` | `pip install qrcode` (oppure ignora: QR disabilitato in UI) |
| `ModuleNotFoundError: sklearn` / altri | `pip install -r requirements.txt` |
| Sidebar assente | Apri il pannello laterale Streamlit (icona freccia) |
| Encrypt fallisce dopo cambio mode | Rigenera la chiave *dopo* aver selezionato il nuovo mode |
| NIST LAB vuoto | Esegui prima Encrypt in Tab 01 |
| ML “not available” | Attendi training iniziale o elimina `cipher_classifier.joblib` e riavvia |
| SMTP auth failed | App Password; “accesso app meno sicure” / policy Google Workspace |
| Argon2 ImportError | `pip install argon2-cffi` |
| PDF non disponibile | `pip install reportlab` oppure usa report `.txt` / ZIP |
| RSA/Hybrid lenti | Normale (generazione chiavi 2048-bit); usa mode AES per demo rapide |

---

## 17. Checklist demo da 5 minuti

Usare questa scaletta in una presentazione:

1. **Avvio** — mostrare header ARMED/ML e workflow.  
2. **Preset Corporate AEAD** → Random Key → Encrypt.  
3. **Pipeline + anatomy** in Tab 01 (30 secondi).  
4. **NIST LAB** — radar e un p-value PASS; heatmap.  
5. **ML CORE** — predizione + “why this prediction”.  
6. **Preset Vigenère** (opzionale) — contrasto con fallimenti statistici.  
7. **ENTERPRISE** — compliance score e download evidence pack.  
8. Chiusura: disclaimer (tool di lab, non certificazione; email chiave solo in demo controllata).

---

## Appendice A — Formati chiave / ciphertext

| Mode (esempi) | Chiave in UI | Ciphertext |
|---------------|--------------|------------|
| Fernet | Stringa url-safe Base64 | Base64 |
| AES-*-GCM / CTR / … | Hex | Hex (spesso nonce\|\|ct\|\|tag) |
| Hybrid / RSA-OAEP | PEM privata | Hex strutturato |

## Appendice B — File generati a runtime

| File | Ruolo |
|------|--------|
| `cipher_classifier.joblib` | Modello ML persistente |
| `crypto_history.csv` | History operazioni |
| Download utente | ZIP evidence, PDF/TXT, case JSON, CSV history |

---

## Appendice C — Sicurezza d’uso del tool

1. Non incollare segreti di produzione reali in demo pubbliche.  
2. Non considerare “PASS NIST” su un singolo messaggio come prova di sicurezza del sistema.  
3. Cancella history e non condividere evidence pack con chiavi in chiaro altrove.  
4. In ambito aziendale, preferisci mode AEAD e KDF con stretching (PBKDF2/scrypt/Argon2id).

---

*Fine guida — Master Crypto Lab v8.1*  
*Documenti correlati: `SINOPSI.md`, `README.md`, `AGENTS.md`*
