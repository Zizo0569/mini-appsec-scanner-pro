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

1. Crée le squelette Quarkus si ce n'est pas déjà fait (via https://code.quarkus.io ou `mvn quarkus:create`).
2. Copie ces fichiers dans ton projet, en respectant l'arborescence `com.zizo.scanner.*`.
3. Ajoute les dépendances de `pom-dependencies-a-ajouter.xml` dans ton `pom.xml`.
4. Crée une base PostgreSQL locale (ou lance-la via Docker) et adapte `application.properties`.
5. Génère les clés JWT :
   ```
   openssl genrsa -out src/main/resources/privateKey.pem 2048
   openssl rsa -in src/main/resources/privateKey.pem -pubout -out src/main/resources/publicKey.pem
   ```
6. Lance : `./mvnw quarkus:dev`

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
