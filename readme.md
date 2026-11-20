How to deploy

create .env

<!-- example -->
POSTGRES_USER=suki_admin
POSTGRES_PASSWORD=suki_password
POSTGRES_DB=suki_teelek
POSTGRES_PORT=5432

PORT=3000
DATABASE_URL=postgres://suki_admin:suki_password@localhost:5432/suki_teelek
JWT_SECRET=suki_teelek_super_secret_jwt_key_2026

docker compose up -d

cd backend

npm install
npm run dev