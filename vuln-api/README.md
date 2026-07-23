# vuln-api — cible de test pour le scanner OpenAPI de rustman

API HTTP **délibérément vulnérable** servant à valider le scanner OpenAPI de
rustman et sa capacité à atteindre **~0 faux positif**. Usage strictement local
(labo, CTF, entraînement red-team).

> ⚠️ **Ne jamais exposer sur un réseau.** Le serveur n'écoute que sur
> `127.0.0.1:8000` et exécute réellement des commandes shell / lit des fichiers
> arbitraires / fait des requêtes sortantes.

## Lancer

```bash
cd vuln-api
go run .          # écoute sur http://127.0.0.1:8000
```

## Scanner avec rustman (CLI)

Mode OpenAPI (endpoints depuis le spec) :

```bash
# depuis la racine du dépôt, une fois vuln-api démarré
cargo run -- --openapi vuln-api/openapi.yaml \
  --target  http://127.0.0.1:8000 \
  --payload-dir payload \
  --format markdown
```

Mode crawler (découverte automatique puis scan, même pipeline ~0 FP) :

```bash
cargo run -- --crawl http://127.0.0.1:8000/ --crawl-depth 2 --format markdown
```

Le crawler part de la page d'index (qui liste tous les endpoints), déduplique les
endpoints découverts, écarte les endpoints destructifs, puis scanne chaque
paramètre injectable via exactement le même moteur que le scanner OpenAPI. Il
gère aussi les **paramètres de chemin** : un segment ressemblant à un identifiant
(`/api/item/1`, UUID, hash) devient `/api/item/{p1}` et est fuzzé. Dans la GUI,
l'onglet **Crawler** expose un bouton « 🛡 Scanner N endpoints (0 FP) ».

Mode import HAR (couvre les SPA : XHR POST/PUT avec corps JSON) :

```bash
# 1) Capturer le trafic (devtools « Save as HAR », proxy, ou le script fourni) :
node tools/capture-har.js http://127.0.0.1:3000/ juice.har --wait 8000
# 2) Scanner chaque requête capturée (corps JSON + chemins à identifiants) :
cargo run -- --import juice.har --target http://127.0.0.1:3000 --format markdown
```

L'import HAR couvre les endpoints d'une SPA que le crawl passif ne soumet pas
(login, feedback…) : chaque champ de corps JSON, chaque paramètre de requête et
chaque segment-identifiant devient fuzzable, toujours via baseline + confirmation
→ ~0 faux positif.

## Audit de contrôle d'accès (IDOR / BOLA / auth manquante)

En plus du fuzzing d'injection, `--import` lance un **audit de contrôle d'accès
différentiel** (façon *Autorize* de Burp) : il rejoue les GET authentifiés sous
un autre contexte et ne conclut que si la **donnée privée du propriétaire** (email
décodé de son JWT) fuit → ~0 faux positif. Seuls les GET sont rejoués (jamais de
POST/PUT/DELETE).

```bash
# HAR capturé en session utilisateur 1 (le token de user1 y figure).
# --bearer2 = token d'un SECOND utilisateur → active le test IDOR/BOLA.
rustman --import user1.har --target http://cible --bearer2 "<token_user2>"
```

- **Auth manquante** : la requête *sans token* renvoie encore l'email privé.
- **IDOR/BOLA** : la requête avec le token de user2 renvoie l'email de user1.

Endpoints de démonstration dans cette API :

| Endpoint | Attendu |
|---|---|
| `GET /api/users/{id}/profile` | **Auth manquante** (email servi sans token) |
| `GET /api/orders/{id}` | **IDOR** (un autre user lit la commande) |
| `GET /api/me` | **Sécurisé** — ne doit jamais être signalé (témoin 0 FP) |

## Endpoints vulnérables (vrais positifs attendus)

| Endpoint | Faille | Déclencheur | Preuve renvoyée |
|---|---|---|---|
| `GET /api/users?id=` | SQLi | guillemet non apparié → erreur SQLite | `SQL logic error: unrecognized token…` |
| `GET /api/account?filter=` | NoSQLi | opérateur `$…` / JS injecté → erreur driver | `MongoServerError: unknown top level operator…` |
| `GET /api/search?q=` | XSS réfléchi | réflexion HTML non échappée | `<script>alert(1)</script>` dans la page |
| `GET /api/ping?host=` | Injection commande | `sh -c "ping -c 1 " + host` | sortie de `id` → `uid=…` |
| `GET /api/file?path=` | Path traversal | `os.ReadFile` sans confinement | contenu de `/etc/passwd` |
| `GET /api/render?tpl=` | SSTI | évalue `ENTIER*ENTIER` dans `{{…}}` etc. | `{{7777*7777}}` → `60481729` |
| `GET /api/fetch?url=` | SSRF | fetch serveur de l'URL fournie | métadonnées cloud / contenu proxifié |
| `GET /api/redirect?url=` | Open redirect | `302` + `Location` non filtré | `Location: http://evil.com` |

## Pièges à faux positifs (aucune vuln ne doit être remontée)

Ces endpoints font échouer un scanner naïf. Le scanner durci ne doit **rien**
remonter dessus.

| Endpoint | Piège | Mécanisme qui l'écarte |
|---|---|---|
| `GET /api/health` | renvoie en permanence `uid=1000(appuser)` et `no such table: …` | **baseline** : les marqueurs sont dans la réponse de référence → filtrés |
| `GET /api/monitor` | renvoie en permanence `connection refused` ; réfléchit aussi le payload (`windows\system32`) | **baseline** (marqueur constant) + **garde de réflexion** (marqueur issu du payload) |
| `GET /api/echo` | réfléchit l'entrée en `application/json` (dont des noms de moteur SSTI) | **gating Content-Type** (JSON ≠ XSS) + **garde de réflexion** |

## Ce que la cible valide côté scanner

1. **Baseline par endpoint** — une requête « propre » sert de référence ; tout
   marqueur déjà présent (health, monitor) est filtré.
2. **Passe de confirmation** — rejeu du payload (anti non-déterminisme) + valeur
   de contrôle bénigne (anti-marqueur indépendant de l'entrée).
3. **Gardes de réflexion** — un marqueur qui provient littéralement du payload
   renvoyé tel quel (`; cat /etc/passwd`, `windows\system32`, `freemarker`…)
   n'est pas une preuve d'exécution.

## Limite connue

Un endpoint qui émettrait un marqueur de façon **purement aléatoire**
(indépendamment de l'entrée) ne peut pas être écarté à coût constant : seule une
confirmation par vote majoritaire (N rejeux) le neutraliserait. Ce cas n'est pas
inclus dans la cible car il ne correspond pas à une vulnérabilité réelle.
