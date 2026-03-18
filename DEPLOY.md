# Deploy dorsal-ml on GPU Machine

dorsal-ml runs on a dedicated GPU machine and communicates with the Control Plane (VPS) via Cloudflare Tunnel — no inbound firewall rules required.

## Architecture

```
VPS (Control Plane)                              GPU Machine (dorsal-ml)
┌─────────────────────────┐                      ┌────────────────────────────┐
│  control:8000           │  POST /runs/trigger  │  dorsal-ml:8090            │
│  DORSAL_ML_URL=         │  X-API-Key: <secret> │  CONTROL_PLANE_URL=        │
│  https://dorsal-ml.     ├──────────────────────►  https://dorsal-api.       │
│  sharkzone.com.br       │                      │  sharkzone.com.br          │
│  cloudflared tunnel     ◄──────────────────────┤  cloudflared tunnel        │
│  dorsal-api.sharkzone   │  PATCH /training/    │  dorsal-ml.sharkzone       │
└─────────────────────────┘  runs/{id}           └────────────────────────────┘
                              POST /ml-models
                              (Bearer JWT)
```

## Prerequisites

- Docker + Docker Compose
- Git
- Access to Cloudflare Zero Trust Dashboard

## 1. Create the Cloudflare Tunnel

1. Go to **Cloudflare Zero Trust Dashboard → Networks → Tunnels → Create Tunnel**
2. Name: `dorsal-ml-gpu`
3. Copy the generated token → save as `CLOUDFLARE_TUNNEL_TOKEN_ML`
4. Add a public hostname:
   - **Subdomain:** `dorsal-ml`
   - **Domain:** `sharkzone.com.br`
   - **Service:** `http://localhost:8090`

## 2. (Optional) Cloudflare Access Policy

Restrict the tunnel so only the Control Plane can reach it:

1. **Zero Trust → Access → Applications → Add Application → Self-hosted**
2. **App URL:** `dorsal-ml.sharkzone.com.br`
3. **Policy:** Block browser access; allow only the Service Token used by the Control Plane

This ensures that only authenticated requests from the VPS reach the endpoint, in addition to the shared API key check.

## 3. Clone and Configure

```bash
git clone <repo> dorsal-ml && cd dorsal-ml
cp .env.example .env
```

Edit `.env` with the actual values:

```env
CONTROL_PLANE_URL=https://dorsal-api.sharkzone.com.br
CONTROL_PLANE_ADMIN_EMAIL=root@dorsal.local
CONTROL_PLANE_ADMIN_PASSWORD=<real-password>
DORSAL_ML_API_KEY=<shared-secret>
CLOUDFLARE_TUNNEL_TOKEN_ML=<token-from-step-1>
TRAIN_MODE=all
```

## 4. Generate and Distribute the Shared API Key

```bash
openssl rand -hex 32
```

Copy the output to:
- `dorsal-ml/.env` → `DORSAL_ML_API_KEY=<value>`
- `dorsal/.env` on the VPS → `DORSAL_ML_API_KEY=<value>`

Both sides must use the same key.

## 5. Start Services

```bash
docker compose up -d --build
docker compose logs -f
```

## 6. Configure the Control Plane (VPS)

In `/home/abraham/tools/dorsal/.env` on the VPS:

```env
DORSAL_ML_URL=https://dorsal-ml.sharkzone.com.br
DORSAL_ML_API_KEY=<same-key-as-above>
```

Restart the control container:

```bash
docker compose restart control
```

## 7. Verify

```bash
# From GPU machine — health via loopback:
curl http://localhost:8090/health
# {"status": "ok"}

# From internet / VPS — health via tunnel:
curl https://dorsal-ml.sharkzone.com.br/health
# {"status": "ok"}

# Trigger without API key — must reject:
curl -X POST https://dorsal-ml.sharkzone.com.br/runs/trigger \
  -H "Content-Type: application/json" -d '{}'
# HTTP 401

# Trigger with API key — must accept:
curl -X POST https://dorsal-ml.sharkzone.com.br/runs/trigger \
  -H "X-API-Key: <key>" \
  -H "Content-Type: application/json" \
  -d '{"run_id":1,"mode":"static","source_ids":[]}'
# HTTP 202
```

## Local Development (Without Tunnel)

To run dorsal-ml alongside the Control Plane on the same machine:

```bash
# In dorsal/ directory:
docker compose --profile ml up
```

`DORSAL_ML_API_KEY` is optional — if unset, `/runs/trigger` is open (safe for local dev behind the Docker network).
