# Master Crypto Lab — Sinossi del progetto

**Versione:** 8.1  
**Tipo:** Laboratorio interattivo di crittografia analitica ed educativa  
**Stack:** Python · Streamlit · cryptography · scikit-learn · Plotly · SciPy  

---

## 1. Cos’è

**Master Crypto Lab** è un’applicazione desktop/web locale pensata per **analizzare, confrontare e spiegare** operazioni crittografiche in modo scientifico. Non è un gestore di password né un prodotto di cifratura “da produzione end-to-end”: è un **banco di prova** (lab) che unisce:

- cifratura e decifratura con **18 modalità** (simmetriche, ibride, asimmetriche, classiche educative);
- **10 metodi di derivazione chiave** (casuale, PBKDF2, scrypt, Argon2id, ECDH, HKDF, …);
- batteria **NIST SP 800-22** (7 test statistici) e metriche ausiliarie;
- **pipeline ML** a 19 feature per classificare il mode di cifratura e rilevare anomalie;
- steganografia LSB, canali email separati (chiave ≠ ciphertext), report e evidence pack per uso dimostrativo/aziendale.

L’interfaccia adotta un linguaggio visivo da **console analitica** (tema scuro, tipografia tecnica, workflow a stadi), con l’obiettivo di risultare credibile in presentazioni e test interni, non come prototipo scolastico generico.

---

## 2. Problema che affronta

In contesti formativi, di security awareness o di pre-assessment, spesso manca uno strumento unico che permetta di:

1. **vedere** cosa succede a un messaggio quando viene cifrato con algoritmi diversi;
2. **misurare** se il ciphertext “sembra casuale” (entropia, test NIST, spettro);
3. **confrontare** modalità forti (AEAD) e deboli (classiche/legacy);
4. **documentare** una sessione di analisi (report, ZIP di evidenze, case file).

Master Crypto Lab concentra questi bisogni in un solo flusso operativo guidato.

---

## 3. Architettura in sintesi

```
Cryptography.py          → UI Streamlit (sidebar + 7 tab + tema console)
crypto_lab/
  crypto_engine.py       → Registry cipher (18) + KDF (10) + padding/IV helpers
  nist_suite.py          → NIST SP 800-22 + feature extraction + viz helpers
  ml_models.py           → RF + MLP + IsolationForest, 19 feature, 10 classi
  steganography.py       → LSB su immagini
  email_service.py       → SMTP: canale chiave / canale ciphertext
  enterprise.py          → Workflow, compliance, benchmark, evidence pack, case file
  pqc_lab.py             → Lab post-quantum educativo (toy KEM + mappa NIST)
  api_server.py          → API REST locale opzionale (FastAPI)
  utils.py / config.py   → Sessione, history CSV, splash, pesi metriche
```

Il design separa **logica di dominio** (`crypto_lab/`) da **presentazione** (`Cryptography.py`), con registry estendibili per cipher e KDF.

---

## 4. Capacità principali

| Area | Contenuto |
|------|-----------|
| **Crittografia** | Fernet, AES-GCM/CBC+HMAC, ChaCha20-Poly1305, CTR/OFB/CFB, XTS, Salsa20, RSA-OAEP, Hybrid RSA+AES-GCM, mode educativi (3DES, Blowfish, XOR+HMAC, Vigenère) |
| **Chiavi** | Random, PBKDF2-SHA256/512, scrypt, Argon2id, HKDF, ECDH X25519, HMAC-seed, hash diretto, KDF a strati; meter di forza password |
| **Analisi** | 7 test NIST, SAC/avalanche, entropy rolling, FFT, heatmap bitstream, anatomy IV/payload/tag, Security Index pesato |
| **ML** | Identificazione mode (10 classi), probabilità, anomaly score, explainability semplificata, model card, retrain su history |
| **Canali** | Email separata per chiave e per ciphertext; QR chiave; stego LSB |
| **Enterprise** | Workflow KEY→ENCRYPT→ANALYZE→EXPORT, compliance C01–C08, benchmark multi-cipher, evidence ZIP/PDF, case file JSON, preset demo, tour guidato |
| **Estensioni** | API locale, lab PQC narrativo (non sostituto di librerie FIPS reali) |

---

## 5. Flusso concettuale

1. **KEY** — Si seleziona il cipher e si genera/deriva una chiave (stato *SYSTEM ARMED*).
2. **ENCRYPT** — Si cifra un plaintext; si ottengono ciphertext, license code, pipeline del mode e anatomia del pacchetto.
3. **ANALYZE** — Si eseguono NIST e grafici scientifici; il ML propone una classificazione del mode.
4. **EXPORT** — Si esporta evidence pack, report, case file; si valutano compliance e benchmark.

La barra di workflow in alto riflette lo stato della sessione su questi quattro stadi.

---

## 6. Destinatari

- **Studenti / docenti** di crittografia e sicurezza applicata  
- **Team security / AppSec** per demo interne e awareness  
- **Analyst** che vogliono un banco di prova statistico su ciphertext  
- **Stakeholder non tecnici** (via report e checklist) in contest di PoC  

**Non** è destinato a: custodia di segreti di produzione, HSM, conformità certificata, o sostituzione di librerie validate in sistemi mission-critical.

---

## 7. Principi di design del prodotto

- **Scientifico:** metriche e test riconducibili a pratiche note (NIST, entropia, AEAD).  
- **Trasparente:** mode educational esplicitamente marcati; model card e limiti del ML dichiarati.  
- **Operativo:** split-channel per email, export audit-style, preset e tour.  
- **Estendibile:** registry cipher/KDF; API locale per integrazioni lab.  

---

## 8. Limiti e disclaimer

- I cipher e i test sono implementati a scopo **analitico/educativo**; la correttezza rispetto a tutti i vettori ufficiali non sostituisce una validazione formale.
- Il modello ML è addestrato in larga parte su **dati sintetici**; le predizioni sono di supporto, non verdetti forensi.
- L’invio di **chiavi via email** è intenzionalmente separato dal ciphertext ma resta un canale a rischio: va usato solo in scenari controllati di demo.
- Il **toy KEM** del lab PQC **non è sicuro** e non implementa ML-KEM/Dilithium reali.

---

## 9. Come si colloca rispetto ad altri tool

| Tool tipico | Master Crypto Lab |
|-------------|-------------------|
| OpenSSL CLI | Meno “lab visuale”, più operazioni raw |
| CyberChef | Più ricette generiche; meno NIST/ML integrati |
| Suite di test NIST standalone | Meno UX e meno cipher registry unificato |
| **Questo progetto** | Unico punto di accesso: cifrare → misurare → classificare → documentare |

---

## 10. Riferimenti rapidi

| Documento | Contenuto |
|-----------|-----------|
| `GUIDA_UTILIZZO.md` | Guida passo-passo all’uso |
| `README.md` | Installazione e elenco feature |
| `AGENTS.md` | Note per sviluppatori / estensione del codice |
| `requirements.txt` | Dipendenze Python |

---

*Master Crypto Lab v8.1 — laboratorio di crittografia analitica per formazione, demo e pre-assessment.*
