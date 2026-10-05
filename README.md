# Mini AppSec Scanner — version Pro

Scanner de posture de sécurité web (headers, HTTPS/certificat, cookies, ports) avec
historique, authentification multi-utilisateurs et scans planifiés.
Stack : **Java 17 + Quarkus + PostgreSQL**.

## Architecture

```
Dashboard (frontend, à part)
        │
        ▼
┌─────────────────────────────┐
│        API backend          │
│  (Java / Quarkus)           │
│                              │
│  ┌────────────────────┐    │
│  │  Scan engine        │    │──▶ Site cible (HTTP/HTTPS)
│  │  headers/https/ports│    │
│  └────────────────────┘    │
│  ┌────────────────────┐    │
│  │  Auth service (JWT) │    │
│  └────────────────────┘    │
│  ┌────────────────────┐    │
│  │  Scheduler          │    │
│  └────────────────────┘    │
└──────────┬───────────────────┘
           ▼
     PostgreSQL (historique)
```

## Ce que fait chaque module

- **`model/`** — entités JPA : `User` (auth) et `ScanResult` (résultat + historique, avec un enum `RiskLevel`).
- **`service/ScanService`** — cœur du scanner : headers de sécurité, cookies (Secure/HttpOnly/SameSite),
  HTTPS + validité/expiration du certificat, scan de ports non intrusif (simple test de connexion TCP),
  et un scoring **pondéré** (chaque header a un poids différent selon sa criticité réelle).
- **`service/AuthService`** — inscription/connexion avec hash bcrypt et émission de JWT (SmallRye JWT).
- **`scheduler/ScanScheduler`** — relance tous les sites suivis toutes les 24h et logue une alerte
  si le score chute de plus de 10 points (à brancher sur un vrai mailer/webhook en prod).
- **`resource/`** — les deux endpoints REST : `/scan` (public) et `/auth/register` + `/auth/login`.

## Lancer le projet

Prérequis : Java 21, Docker (et Maven, ou le wrapper `mvnw` fourni).

1. Clone le dépôt et place-toi dedans :
```
   git clone https://github.com/Zizo0569/mini-appsec-scanner-pro.git
   cd mini-appsec-scanner-pro
```
2. Lance PostgreSQL avec Docker (les identifiants correspondent à `application.properties`) :
```
   docker run -d --name appsec-db -e POSTGRES_USER=scanner_user -e POSTGRES_PASSWORD=change-me -e POSTGRES_DB=appsec_scanner -p 5434:5432 postgres:16
```
3. Génère les clés JWT (elles ne sont pas dans le dépôt, volontairement) :
```
   openssl genrsa -out src/main/resources/privateKey.pem 2048
   openssl rsa -in src/main/resources/privateKey.pem -pubout -out src/main/resources/publicKey.pem
```
4. Démarre l'application :
```
   ./mvnw quarkus:dev
```
5. Ouvre http://localhost:8082/ : l'interface web permet de saisir une URL et d'afficher le résultat du scan.
## Tester rapidement

```powershell
# Inscription
Invoke-RestMethod -Uri "http://localhost:8082/auth/register" -Method Post -ContentType "application/json" -Body '{"username":"zizo","password":"MonMotDePasse123"}'

# Connexion (récupère le token JWT)
Invoke-RestMethod -Uri "http://localhost:8082/auth/login" -Method Post -ContentType "application/json" -Body '{"username":"zizo","password":"MonMotDePasse123"}'

# Scan (public, pas besoin de token)
Invoke-RestMethod -Uri "http://localhost:8082/scan" -Method Post -ContentType "application/json" -Body '{"url":"https://zizo0569.github.io/Dr.Marouane_HABLA/"}'
```

## Pistes d'évolution (pour la soutenance)

- Détection de CVE via l'API NVD sur les technologies identifiées (header `Server`)
- Vérification SPF/DKIM/DMARC sur le domaine
- Export du rapport en PDF
- Dashboard React/Vue au lieu d'appels API bruts
- Alerting réel (email via Quarkus Mailer, ou webhook Slack/Discord)

## Notes de sécurité importantes

- Le scan de ports est volontairement **non intrusif** (simple test de connexion TCP, pas de scan agressif type Nmap SYN) —
  utile pour rester dans un usage légal et éthique : ne scanne que des sites dont tu es propriétaire ou que tu es autorisé à tester.
- Change `change-me` dans `application.properties` avant tout déploiement réel.
