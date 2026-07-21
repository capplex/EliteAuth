# Deployment

## 1. Database

Create a Supabase project and run, in order:

1. `supabase/migrations/001_initial_schema.sql`
2. `supabase/migrations/002_signed_responses_and_anti_tamper.sql`

Configure Supabase Authentication site and redirect URLs for your domain.

## 2. Website

Edit `website/supabase-config.js` with your public Supabase project URL and publishable key. Deploy the contents of `website/` to a static host.

For a local preview:

```bash
docker compose up -d
```

## 3. API Worker

```bash
cd worker
cp wrangler.toml.example wrangler.toml
npm install
```

Set these as encrypted Worker secrets:

- `SUPABASE_SERVICE_ROLE_KEY`
- `ELITEAUTH_SIGNING_PRIVATE_JWK`

Set `SUPABASE_URL` and `ALLOWED_ORIGIN` as environment variables, then deploy:

```bash
npm run deploy
```

Generate a signing key with `node scripts/generate-signing-key.mjs`. Keep the private JWK secret and pin only the public key in trusted clients.
