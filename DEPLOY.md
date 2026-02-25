# AuditAgent — Deploy Guide

## Estructura

```
auditagent/
├── api/
│   ├── main.py            ← Backend FastAPI (Railway)
│   ├── requirements.txt
│   ├── Procfile
│   └── railway.json
├── frontend/
│   └── index.html         ← Frontend estático (Vercel)
├── vercel.json
├── .gitignore
└── DEPLOY.md
```

---

## PASO 1 — Subir a GitHub

```bash
git init
git add .
git commit -m "Initial commit — AuditAgent"
git remote add origin https://github.com/TU_USUARIO/auditagent.git
git push -u origin main
```

---

## PASO 2 — Deploy del backend en Railway

1. Ve a **https://railway.app** → New Project → **Deploy from GitHub repo**
2. Selecciona tu repo `auditagent`
3. En **Settings → Source**:
   - Root Directory: `api`
4. Railway detecta automáticamente `Procfile` y `requirements.txt`
5. Click **Deploy**
6. Cuando termine, ve a **Settings → Networking → Generate Domain**
7. Copia la URL que Railway te da. Ejemplo:
   ```
   https://auditagent-production-abc123.up.railway.app
   ```

**Verificar que funciona:**
```
https://TU_URL.up.railway.app/
```
Debe devolver: `{"status":"ok","service":"AuditAgent API","version":"1.0.0","network":"Base"}`

---

## PASO 3 — Conectar frontend con backend

Abre `frontend/index.html` y busca la línea:

```javascript
const API_BASE = 'https://YOUR_RAILWAY_URL.up.railway.app';
```

Reemplaza con tu URL real:

```javascript
const API_BASE = 'https://auditagent-production-abc123.up.railway.app';
```

Guarda el archivo, haz commit y push:

```bash
git add frontend/index.html
git commit -m "Set Railway API URL"
git push
```

---

## PASO 4 — Deploy del frontend en Vercel

1. Ve a **https://vercel.com** → New Project → Import Git Repository
2. Selecciona tu repo `auditagent`
3. Vercel detecta `vercel.json` automáticamente — no cambies nada
4. Click **Deploy**
5. En unos segundos tendrás tu URL de Vercel

---

## PASO 5 — Agregar tu dominio

En Vercel:
1. **Settings → Domains → Add Domain**
2. Escribe tu dominio, ejemplo `auditagent.xyz`
3. Vercel te dará registros DNS (A record o CNAME)
4. Agrégalos en tu registrador de dominio
5. Espera 5-15 min para propagación

---

## PASO 6 — Probar en producción

1. Abre tu dominio en el browser
2. Busca un contrato verificado en https://basescan.org
   - Ejemplo: USDC en Base: `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`
3. Pega la address, tu Anthropic key y click en **AUDIT CONTRACT**

---

## Correr localmente (desarrollo)

```bash
# Terminal 1 — Backend
cd api
python -m venv .venv
source .venv/bin/activate        # Mac/Linux
# .venv\Scripts\activate         # Windows
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Terminal 2 — Frontend
cd frontend
python -m http.server 3000
```

Abre `http://localhost:3000`

En `frontend/index.html` cambia temporalmente:
```javascript
const API_BASE = 'http://localhost:8000';
```

---

## Variables de entorno

El backend **no requiere ninguna variable de entorno**.
Las API keys las introduce el usuario en el formulario y se usan solo durante la request.

---

## Costos

| Servicio      | Plan          | Costo            |
|---------------|---------------|------------------|
| Vercel        | Hobby         | **Gratis**       |
| Railway       | Starter       | **~$0-5/mes**    |
| Anthropic     | Paga el usuario | **$0 para ti** |
| Basescan      | Free tier     | **Gratis**       |
