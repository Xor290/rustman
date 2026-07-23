// vuln-api — API HTTP délibérément vulnérable pour tester le scanner OpenAPI de
// rustman en environnement légal (labo local, CTF, red-team training).
//
// ⚠️  NE JAMAIS EXPOSER SUR UN RÉSEAU. Écoute sur 127.0.0.1 uniquement.
//
// Elle expose deux familles d'endpoints :
//   - Vulnérables (vrais positifs) : SQLi, XSS, CMDi, PathTraversal, SSTI,
//     SSRF, OpenRedirect — chacun renvoie exactement le marqueur que le
//     détecteur de rustman recherche lorsqu'il est exploité.
//   - Pièges à faux positifs : endpoints dont la réponse *normale* contient
//     déjà un marqueur, ou dont la réponse est non-déterministe. Un scanner
//     sans baseline + confirmation les signalerait à tort ; le scanner durci
//     ne doit remonter AUCUNE vuln sur ces endpoints.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const addr = "127.0.0.1:8000"

func main() {
	mux := http.NewServeMux()

	// ── Endpoints vulnérables (vrais positifs attendus) ──────────────────────
	mux.HandleFunc("/api/users", sqliHandler)         // SQLi (query param)
	mux.HandleFunc("/api/item/", sqliPathHandler)     // SQLi (path param)
	mux.HandleFunc("/api/login", sqliLoginHandler)    // SQLi (POST JSON body)
	mux.HandleFunc("/api/account", nosqlHandler)      // NoSQLi (MongoDB)
	mux.HandleFunc("/api/me", accMeHandler)           // contrôle d'accès : SÉCURISÉ (témoin)
	mux.HandleFunc("/api/orders/", accOrdersHandler)  // contrôle d'accès : IDOR/BOLA
	mux.HandleFunc("/api/users/", accUsersHandler)    // contrôle d'accès : auth manquante
	mux.HandleFunc("/api/search", xssHandler)         // XSS réfléchi (HTML)
	mux.HandleFunc("/api/ping", cmdiHandler)          // Injection de commande
	mux.HandleFunc("/api/file", pathTraversalHandler) // Path traversal
	mux.HandleFunc("/api/render", sstiHandler)        // SSTI
	mux.HandleFunc("/api/fetch", ssrfHandler)         // SSRF
	mux.HandleFunc("/api/redirect", openRedirectHandler)

	// ── Pièges à faux positifs (aucune vuln ne doit être remontée) ───────────
	mux.HandleFunc("/api/health", healthHandler)  // marqueurs constants (uid=, erreur SQL)
	mux.HandleFunc("/api/monitor", monitorHandler) // "connection refused" constant
	mux.HandleFunc("/api/echo", echoHandler)       // réflexion en JSON (pas du XSS)

	mux.HandleFunc("/", rootHandler)

	log.Printf("vuln-api à l'écoute sur http://%s (127.0.0.1 uniquement)", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Page d'index liant tous les endpoints (avec un paramètre d'exemple) pour
	// que le crawler les découvre et les transmette au scanner.
	fmt.Fprint(w, `<html><body>
<h1>vuln-api</h1>
<p>Cible de test rustman.</p>
<ul>
  <li><a href="/api/users?id=1">users</a></li>
  <li><a href="/api/item/1">item (path param)</a></li>
  <li><a href="/api/account?filter=admin">account</a></li>
  <li><a href="/api/search?q=hello">search</a></li>
  <li><a href="/api/ping?host=127.0.0.1">ping</a></li>
  <li><a href="/api/file?path=readme.txt">file</a></li>
  <li><a href="/api/render?tpl=hello">render</a></li>
  <li><a href="/api/fetch?url=http://127.0.0.1:8000/">fetch</a></li>
  <li><a href="/api/redirect?url=/home">redirect</a></li>
  <li><a href="/api/health?verbose=1">health</a></li>
  <li><a href="/api/monitor?target=db">monitor</a></li>
  <li><a href="/api/echo?msg=hi">echo</a></li>
</ul>
</body></html>`)
}

// ── SQLi ─────────────────────────────────────────────────────────────────────
// Concatène l'entrée dans une requête SQL. Un guillemet non apparié casse la
// syntaxe → on renvoie une erreur SQLite, exactement ce que le détecteur SQLi
// recherche. Une entrée bénigne (« test ») ne casse rien → pas d'erreur.
func sqliHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT id, username FROM users WHERE id = '%s'", id)

	if strings.Count(id, "'")%2 == 1 || strings.Count(id, "\"")%2 == 1 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"SQL logic error: unrecognized token near %q","query":%q}`,
			id, query)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"query":%q,"results":[]}`, query)
}

// ── SQLi via paramètre de chemin ──────────────────────────────────────────────
// `/api/item/<id>` interpole le dernier segment dans une requête SQL. Un
// guillemet non apparié casse la syntaxe → erreur SQLite.
func sqliPathHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/item/")
	query := fmt.Sprintf("SELECT * FROM items WHERE id = '%s'", id)
	w.Header().Set("Content-Type", "application/json")
	if strings.Count(id, "'")%2 == 1 || strings.Count(id, "\"")%2 == 1 {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"SQL logic error: unrecognized token near %q","query":%q}`, id, query)
		return
	}
	fmt.Fprintf(w, `{"query":%q,"item":null}`, query)
}

// ── SQLi via corps JSON (POST) ────────────────────────────────────────────────
// `POST /api/login {username,password}` interpole `username` dans une requête
// SQL → injectable via le corps.
func sqliLoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", body.Username)
	if strings.Count(body.Username, "'")%2 == 1 {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"SQL logic error: unrecognized token near %q","query":%q}`, body.Username, query)
		return
	}
	fmt.Fprintf(w, `{"query":%q,"authenticated":false}`, query)
}

// ── NoSQLi (MongoDB) ──────────────────────────────────────────────────────────
// Interpole l'entrée dans une requête MongoDB. Un opérateur (`$…`) ou une chaîne
// JS non terminée fait remonter une erreur du driver (MongoServerError), ce que
// le détecteur NoSQLi recherche. Une entrée bénigne (« test ») ne casse rien.
func nosqlHandler(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	w.Header().Set("Content-Type", "application/json")

	injected := strings.Contains(filter, "$") ||
		strings.Count(filter, "'")%2 == 1 ||
		strings.Count(filter, "\"")%2 == 1
	if injected {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w,
			`{"error":"MongoServerError: unknown top level operator: %s. Full error: {ok:0,code:2}","query":"db.users.find({username:'%s'})"}`,
			filter, filter)
		return
	}
	fmt.Fprintf(w, `{"query":"db.users.find({username:'%s'})","results":[]}`, filter)
}

// ── XSS réfléchi ──────────────────────────────────────────────────────────────
// Réinjecte l'entrée dans une page HTML sans échappement. Content-Type text/html
// pour que le détecteur XSS considère la réflexion comme exploitable.
func xssHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body><h1>Résultats pour : %s</h1></body></html>", q)
}

// ── Injection de commande ─────────────────────────────────────────────────────
// Concatène l'entrée dans une commande shell. « ; id » exécute `id` → uid=…
func cmdiHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, _ := exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(out)
}

// ── Path traversal ────────────────────────────────────────────────────────────
// Lit un fichier sans normaliser le chemin. « ../../../etc/passwd » sort du
// répertoire prévu.
func pathTraversalHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("path")
	if name == "" {
		http.Error(w, "path manquant", http.StatusBadRequest)
		return
	}
	// Volontairement vulnérable : pas de filepath.Clean ni de vérification de
	// confinement dans le répertoire.
	data, err := readFileLoose(name)
	if err != nil {
		http.Error(w, "impossible de lire le fichier", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(data)
}

// ── SSTI ──────────────────────────────────────────────────────────────────────
// Mini-moteur de template vulnérable : évalue toute expression arithmétique
// « ENTIER*ENTIER » trouvée dans {{…}}, ${…}, #{…} ou <%= … %>.
// {{7777*7777}} → 60493729, ce que le détecteur SSTI recherche.
var tplExpr = regexp.MustCompile(`(?:\{\{|\$\{|#\{|<%=)\s*([0-9]+)\s*\*\s*([0-9]+)\s*(?:\}\}|\}|%>)`)

func sstiHandler(w http.ResponseWriter, r *http.Request) {
	tpl := r.URL.Query().Get("tpl")
	rendered := tplExpr.ReplaceAllStringFunc(tpl, func(m string) string {
		sub := tplExpr.FindStringSubmatch(m)
		a := atoi(sub[1])
		b := atoi(sub[2])
		return fmt.Sprintf("%d", a*b)
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body>%s</body></html>", rendered)
}

// ── SSRF ──────────────────────────────────────────────────────────────────────
// Récupère l'URL fournie côté serveur et renvoie le contenu. Les hôtes de
// métadonnées cloud renvoient de fausses credentials ; les autres URLs sont
// réellement fetchées et proxifiées (headers/status/body dans du JSON).
func ssrfHandler(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	w.Header().Set("Content-Type", "application/json")

	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid url: %s"}`, raw)
		return
	}

	// Simulation des endpoints de métadonnées cloud internes.
	if isMetadataHost(u.Host) {
		fmt.Fprint(w, `{"AccessKeyId":"ASIAEXAMPLE","aws_secret_access_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Token":"FAKE"}`)
		return
	}

	resp, err := http.Get(raw) // vulnérable : aucune validation de la cible
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, `{"error":"failed to connect: %s"}`, err.Error())
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	headers := map[string]string{}
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}
	out := map[string]any{
		"status":  resp.StatusCode,
		"headers": headers,
		"body":    string(body),
	}
	json.NewEncoder(w).Encode(out)
}

// ── Open redirect ─────────────────────────────────────────────────────────────
// Redirige vers l'URL fournie sans liste blanche.
func openRedirectHandler(w http.ResponseWriter, r *http.Request) {
	dest := r.URL.Query().Get("url")
	if dest == "" {
		http.Error(w, "url manquante", http.StatusBadRequest)
		return
	}
	w.Header().Set("Location", dest)
	w.WriteHeader(http.StatusFound) // 302
}

// ════════════════════════════════════════════════════════════════════════════
//  Pièges à faux positifs — le scanner durci ne doit RIEN remonter ici.
// ════════════════════════════════════════════════════════════════════════════

// /api/health : renvoie TOUJOURS un diagnostic contenant `uid=1000(appuser)` et
// une ligne d'erreur SQL, quelle que soit l'entrée. Sans baseline, un scanner
// signalerait CMDi + SQLi. Avec baseline, ces marqueurs sont dans la réponse de
// référence → filtrés.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, "status: ok\n")
	fmt.Fprint(w, "runtime user: uid=1000(appuser) gid=1000(appuser) groups=1000(appuser)\n")
	fmt.Fprint(w, "last cache warmup: no such table: cache_v2 (ignored)\n")
	fmt.Fprintf(w, "checked param: %s\n", r.URL.Query().Get("verbose"))
}

// /api/monitor : renvoie TOUJOURS une ligne de log « connection refused »,
// indépendamment de l'entrée. Piège SSRF filtré par la baseline.
func monitorHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, "monitor report\n")
	fmt.Fprint(w, "upstream db: connection refused (retry scheduled)\n")
	fmt.Fprintf(w, "target: %s\n", r.URL.Query().Get("target"))
}

// /api/echo : réfléchit l'entrée mais en JSON (application/json). Une réflexion
// dans du JSON n'est pas un XSS exploitable → le détecteur XSS l'ignore déjà.
func echoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"msg": r.URL.Query().Get("msg")})
}

// ════════════════════════════════════════════════════════════════════════════
//  Contrôle d'accès (test de l'audit IDOR / auth manquante)
// ════════════════════════════════════════════════════════════════════════════
//
// Modèle de token : JWT « none » dont le payload (segment central, base64url) est
// {"data":{"email":"...","id":N}}. userEmail(id) = victimN@corp.local.

func decodeToken(r *http.Request) (string, int, bool) {
	a := r.Header.Get("Authorization")
	if !strings.HasPrefix(a, "Bearer ") {
		return "", 0, false
	}
	parts := strings.Split(strings.TrimPrefix(a, "Bearer "), ".")
	if len(parts) < 2 {
		return "", 0, false
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if data, err = base64.URLEncoding.DecodeString(parts[1]); err != nil {
			return "", 0, false
		}
	}
	var p struct {
		Data struct {
			Email string `json:"email"`
			ID    int    `json:"id"`
		} `json:"data"`
	}
	if json.Unmarshal(data, &p) != nil || p.Data.Email == "" {
		return "", 0, false
	}
	return p.Data.Email, p.Data.ID, true
}

func userEmail(id int) string { return fmt.Sprintf("victim%d@corp.local", id) }

// /api/me — SÉCURISÉ (témoin) : renvoie l'email DU TOKEN, exige un token valide.
// L'audit ne doit RIEN remonter : anonyme → 401 ; autre user → son propre email.
func accMeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	email, id, ok := decodeToken(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"authentication required"}`)
		return
	}
	fmt.Fprintf(w, `{"id":%d,"email":%q}`, id, email)
}

// /api/orders/<id> — IDOR : exige un token valide MAIS ne vérifie pas la
// propriété → n'importe quel utilisateur lit la commande d'un autre.
func accOrdersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if _, _, ok := decodeToken(r); !ok {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"authentication required"}`)
		return
	}
	id := atoi(strings.TrimPrefix(r.URL.Path, "/api/orders/"))
	fmt.Fprintf(w, `{"orderId":%d,"owner":%q,"total":42.00}`, id, userEmail(id))
}

// /api/users/<id>/profile — AUTH MANQUANTE : renvoie le profil (email privé) sans
// aucune vérification d'authentification.
func accUsersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	seg := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/api/users/"), "/", 2)
	id := atoi(seg[0])
	fmt.Fprintf(w, `{"id":%d,"email":%q,"role":"customer"}`, id, userEmail(id))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func readFileLoose(name string) ([]byte, error) {
	// Volontairement vulnérable : lit le chemin tel quel, sans normalisation ni
	// confinement dans un répertoire. Les « ../ » remontent librement.
	return os.ReadFile(name)
}

func isMetadataHost(host string) bool {
	h := strings.ToLower(host)
	for _, m := range []string{
		"169.254.169.254",
		"metadata.google.internal",
		"100.100.100.200",
	} {
		if strings.HasPrefix(h, m) {
			return true
		}
	}
	return false
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
