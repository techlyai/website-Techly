# Techly website

Node.js (Express) server that serves the static site in `public/` and the
AI × SI Master Class admissions API, backed by MongoDB.

| URL | What |
|---|---|
| `/` | Main Techly site (`public/index.html`) |
| `/courses.html` | AI × SI Master Class page + admission form |
| `/admin` | Admin panel (email + password login). `/courses/admin` and `/courses.html/admin` also work. |

## Run locally

```bash
npm install
cp .env.example .env      # then fill in MONGODB_URI and JWT_SECRET
npm run create-owner -- you@example.com "a-strong-password" "Your Name"
npm run dev               # http://localhost:4000
```

## Deploy (Dokploy)

Build with the `Dockerfile` (container port 80). Set these environment variables in Dokploy:

- `MONGODB_URI`: use the **internal** connection URL of the Dokploy Mongo service
  (URL-encode `@` in the password as `%40`)
- `MONGODB_DB=techly`
- `JWT_SECRET`: long random string
- Do **not** set `COOKIE_SECURE` (defaults to secure cookies over https)

Create the first Owner once, from the Dokploy app terminal:
`node scripts/create-owner.js you@example.com "a-strong-password" "Your Name"`

## Data (MongoDB database `techly`)

- `applications`: student registrations (unique `admissionId`, unique `utr`)
- `screenshots`: payment screenshot images (max 5 MB each)
- `settings`: `_id: "payment"` holds UPI ID, payee, WhatsApp, next batch date
- `admins`: admin users (email, name, role Owner/Admin, bcrypt password hash)
