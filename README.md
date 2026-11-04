# StockevikBackend

Testbackend för Det händer i Stockevik.

Node.js + Express + PostgreSQL. Separat från LakeVic.

## Render (senare steg)
Build: `npm install`
Start: `npm start`
Databasanslutningen (`DATABASE_URL`) och eventuella testlösenord ska anges som miljövariabler i Render – aldrig sparas i Git.

Hälsokontroll: `GET /api/health`.

`SEED_DEMO=true` används endast med tre separata testlösenord (minst 12 tecken). Lägg aldrig riktiga medlemsuppgifter i testmiljön.

Frontend 0.5 är ännu inte kopplad till detta API.
