// VulnAPI — API Go délibérément vulnérable à des fins éducatives
// Couvre l'OWASP Top 10 (2021)
// NE PAS DÉPLOYER EN PRODUCTION
package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"text/template"
	"time"

	_ "modernc.org/sqlite"
)

// ─── Modèles ─────────────────────────────────────────────────────────────────

type User struct {
	ID         int    `json:"id"`
	Username   string `json:"username"`
	Password   string `json:"password"` // A02: hash MD5 exposé en réponse
	Email      string `json:"email"`
	Role       string `json:"role"`
	IsAdmin    bool   `json:"is_admin"`
	CreditCard string `json:"credit_card"` // A02: données sensibles stockées en clair
	SSN        string `json:"ssn"`
	APIKey     string `json:"api_key"`
	ResetToken string `json:"reset_token,omitempty"`
}

// A07: token = base64(JSON) sans signature — totalement falsifiable
type Token struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	IsAdmin  bool   `json:"is_admin"`
	Exp      int64  `json:"exp"` // jamais vérifié
}

// ─── Base de données ──────────────────────────────────────────────────────────

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "/tmp/vulnapi.db")
	if err != nil {
		log.Fatal(err)
	}

	db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		username    TEXT UNIQUE,
		password    TEXT,
		email       TEXT,
		role        TEXT    DEFAULT 'user',
		is_admin    INTEGER DEFAULT 0,
		credit_card TEXT,
		ssn         TEXT,
		api_key     TEXT,
		reset_token TEXT
	)`)

	db.Exec(`CREATE TABLE IF NOT EXISTS posts (
		id      INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		title   TEXT,
		content TEXT,
		secret  TEXT
	)`)

	db.Exec(`INSERT OR IGNORE INTO users
		(username, password, email, role, is_admin, credit_card, ssn, api_key)
	VALUES
		('admin', '` + md5sum("admin123") + `', 'admin@corp.local', 'admin', 1,
		 '4111111111111111', '123-45-6789', 'sk-prod-super-secret-key'),
		('alice', '` + md5sum("password") + `', 'alice@example.com', 'user', 0,
		 '4222222222222222', '987-65-4321', 'sk-alice-api-key'),
		('bob',   '` + md5sum("bob123") + `',   'bob@example.com',   'user', 0,
		 '4333333333333333', '111-22-3333', 'sk-bob-api-key')`)

	db.Exec(`INSERT OR IGNORE INTO posts (user_id, title, content, secret) VALUES
		(1, 'Admin memo',  'Confidentiel', 'FLAG{sqli_union_select}'),
		(2, 'Post alice',  'Hello world',  'FLAG{idor_works}'),
		(3, 'Post bob',    'Test post',    'FLAG{access_control_broken}')`)
}

// ─── Utilitaires auth ─────────────────────────────────────────────────────────

func md5sum(s string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(s)))
}

// A02: token = base64(json), aucune signature HMAC
func generateToken(u User) string {
	t := Token{
		UserID:   u.ID,
		Username: u.Username,
		Role:     u.Role,
		IsAdmin:  u.IsAdmin,
		Exp:      time.Now().Add(24 * time.Hour).Unix(),
	}
	data, _ := json.Marshal(t)
	return base64.StdEncoding.EncodeToString(data)
}

// A07: aucune vérification de signature ni d'expiration
func parseToken(raw string) (*Token, error) {
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var t Token
	return &t, json.Unmarshal(data, &t)
}

func bearerToken(r *http.Request) (*Token, bool) {
	h := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if h == "" {
		return nil, false
	}
	t, err := parseToken(h)
	return t, err == nil
}

// ─── Helpers JSON ─────────────────────────────────────────────────────────────

func jsonWrite(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	// A05: CORS wildcard — tout origine autorisée
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	jsonWrite(w, code, map[string]string{"error": msg})
}

func jsonOK(w http.ResponseWriter, msg string) {
	jsonWrite(w, 200, map[string]string{"message": msg})
}

// ─── Routeur ──────────────────────────────────────────────────────────────────

func main() {
	initDB()

	mux := http.NewServeMux()

	// A01 — Broken Access Control
	mux.HandleFunc("/api/users", handleUsers) // liste sans auth
	mux.HandleFunc("/api/users/", handleUser) // IDOR + update sans ownership check
	mux.HandleFunc("/api/admin", handleAdmin) // clé statique ou token forgeable
	mux.HandleFunc("/api/files", handleFiles) // path traversal

	// A02 — Cryptographic Failures
	// (démontré via MD5, token base64, données sensibles en clair dans toutes les réponses)

	// A03 — Injection
	mux.HandleFunc("/api/search", handleSearch)     // SQL injection
	mux.HandleFunc("/api/exec", handleExec)         // command injection
	mux.HandleFunc("/api/xml", handleXML)           // XXE pattern
	mux.HandleFunc("/api/template", handleTemplate) // SSTI (text/template + funcMap dangereux)

	// A04 — Insecure Design / Mass Assignment
	mux.HandleFunc("/api/register", handleRegister) // mass assignment : role, is_admin, etc.

	// A05 — Security Misconfiguration
	mux.HandleFunc("/api/debug", handleDebug)   // endpoint debug toujours actif
	mux.HandleFunc("/api/config", handleConfig) // secrets hardcodés exposés

	// A07 — Identification & Authentication Failures
	mux.HandleFunc("/api/login", handleLogin) // no rate-limit, SQLi, token forgeable
	mux.HandleFunc("/api/reset", handleReset) // token prédictible, pas d'expiration

	// A10 — SSRF
	mux.HandleFunc("/api/fetch", handleFetch)

	// A05: Stack traces activées, pas de TLS
	log.Println("[*] VulnAPI démarré sur http://0.0.0.0:8090")
	log.Println("[*] DB: /tmp/vulnapi.db | Comptes: admin/admin123, alice/password, bob/bob123")
	log.Fatal(http.ListenAndServe("0.0.0.0:8090", mux))
}

// ═══════════════════════════════════════════════════════════════════════════════
// A04 — Mass Assignment + A02 — MD5 password hashing
// POST /api/register
// Exploit: {"username":"hacker","password":"x","role":"admin","is_admin":true}
// ═══════════════════════════════════════════════════════════════════════════════

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", 405)
		return
	}

	var u User
	// A04: décode TOUS les champs JSON, y compris role et is_admin
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		jsonErr(w, "JSON invalide", 400)
		return
	}
	if u.Username == "" || u.Password == "" {
		jsonErr(w, "username et password requis", 400)
		return
	}

	// A02: MD5 pour le hachage — trivial à reverser
	u.Password = md5sum(u.Password)

	isAdmin := 0
	if u.IsAdmin {
		isAdmin = 1
	}

	res, err := db.Exec(
		`INSERT INTO users (username,password,email,role,is_admin,credit_card,ssn) VALUES (?,?,?,?,?,?,?)`,
		u.Username, u.Password, u.Email, u.Role, isAdmin, u.CreditCard, u.SSN,
	)
	if err != nil {
		// A05: message d'erreur DB verbeux
		jsonErr(w, fmt.Sprintf("Erreur DB: %v", err), 500)
		return
	}

	id, _ := res.LastInsertId()
	u.ID = int(id)

	// A02: retourne le hash MD5 et les données sensibles dans la réponse
	jsonWrite(w, 201, map[string]any{
		"message": "Utilisateur créé",
		"user":    u,
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// A07 — Auth Failures + A03 — SQL Injection dans le login
// POST /api/login
// Exploit SQLi: {"username":"admin'--","password":"n'importe quoi"}
// ═══════════════════════════════════════════════════════════════════════════════

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", 405)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	json.NewDecoder(r.Body).Decode(&creds)

	// A03: concaténation directe → SQL injection
	// Exploit: username = admin'--
	query := fmt.Sprintf(
		"SELECT id,username,email,role,is_admin,credit_card,ssn,api_key FROM users WHERE username='%s' AND password='%s'",
		creds.Username, md5sum(creds.Password),
	)

	row := db.QueryRow(query)
	var u User
	var isAdmin int
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &isAdmin, &u.CreditCard, &u.SSN, &u.APIKey)
	u.IsAdmin = isAdmin == 1

	if err != nil {
		if err == sql.ErrNoRows {
			// A07: distingue "utilisateur inconnu" de "mauvais mot de passe" → user enumeration
			jsonErr(w, "Identifiants invalides", 401)
		} else {
			// A05: expose la requête SQL complète en cas d'erreur
			jsonErr(w, fmt.Sprintf("Erreur DB: %v\nRequête: %s", err, query), 500)
		}
		return
	}

	token := generateToken(u)

	// A07: pas de rate-limiting, pas de lockout, token forgeable
	// A02: retourne toutes les données sensibles dans la réponse de login
	jsonWrite(w, 200, map[string]any{
		"token": token,
		"user":  u,
		"hint":  "Le token est base64(json) — essayez de le modifier !",
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// A01 — Broken Access Control : liste tous les utilisateurs sans authentification
// GET /api/users
// ═══════════════════════════════════════════════════════════════════════════════

func handleUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", 405)
		return
	}

	// A01: aucune vérification d'authentification
	rows, err := db.Query("SELECT id,username,email,role,is_admin,credit_card,ssn,api_key FROM users")
	if err != nil {
		jsonErr(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		var isAdmin int
		rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &isAdmin, &u.CreditCard, &u.SSN, &u.APIKey)
		u.IsAdmin = isAdmin == 1
		users = append(users, u)
	}

	jsonWrite(w, 200, users)
}

// ═══════════════════════════════════════════════════════════════════════════════
// A01 — IDOR + Mass Assignment via PUT
// GET  /api/users/{id}  → lit n'importe quel profil
// PUT  /api/users/{id}  → modifie n'importe quel champ (SQLi sur colonne)
// DELETE /api/users/{id} → supprime n'importe quel compte
// ═══════════════════════════════════════════════════════════════════════════════

func handleUser(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/users/"), "/")
	id := parts[0]
	if id == "" {
		jsonErr(w, "ID manquant", 400)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// A01: IDOR — aucune vérification que l'id appartient au token
		row := db.QueryRow(
			"SELECT id,username,email,role,is_admin,credit_card,ssn,api_key FROM users WHERE id=?", id,
		)
		var u User
		var isAdmin int
		if err := row.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &isAdmin, &u.CreditCard, &u.SSN, &u.APIKey); err != nil {
			jsonErr(w, "Utilisateur introuvable", 404)
			return
		}
		u.IsAdmin = isAdmin == 1
		jsonWrite(w, 200, u)

	case http.MethodPut:
		// A01: peut modifier N'IMPORTE QUEL utilisateur
		// A04: mass assignment — role, is_admin, credit_card, etc.
		// A03: SQLi via le nom de colonne non validé
		// Exploit: {"role": "admin', is_admin=1, username=hacked --"}
		var updates map[string]any
		if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
			jsonErr(w, "JSON invalide", 400)
			return
		}
		for col, val := range updates {
			// A03: nom de colonne non échappé → injection sur la structure
			query := fmt.Sprintf("UPDATE users SET %s='%v' WHERE id=%s", col, val, id)
			if _, err := db.Exec(query); err != nil {
				jsonErr(w, fmt.Sprintf("Erreur: %v | Requête: %s", err, query), 500)
				return
			}
		}
		jsonOK(w, "Utilisateur mis à jour")

	case http.MethodDelete:
		// A01: supprime n'importe quel compte sans vérification d'appartenance
		db.Exec("DELETE FROM users WHERE id=?", id)
		jsonOK(w, "Utilisateur supprimé")

	default:
		http.Error(w, "Method Not Allowed", 405)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// A03 — SQL Injection (UNION-based, error-based, table/colonne contrôlée)
// GET /api/search?q=&table=
// Exploit: ?q=' UNION SELECT 1,username,password,email,role,credit_card,ssn,api_key FROM users--
// ═══════════════════════════════════════════════════════════════════════════════

func handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	table := r.URL.Query().Get("table")
	if table == "" {
		table = "posts"
	}

	// A03: table et q non validés → SQLi + injection de table
	query := fmt.Sprintf(
		"SELECT * FROM %s WHERE title LIKE '%%%s%%' OR content LIKE '%%%s%%'",
		table, q, q,
	)

	rows, err := db.Query(query)
	if err != nil {
		// A05: retourne la requête SQL complète en cas d'erreur
		jsonErr(w, fmt.Sprintf("Erreur: %v\nRequête: %s", err, query), 500)
		return
	}
	defer rows.Close()

	cols, _ := rows.Columns()
	var results []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		rows.Scan(ptrs...)
		row := make(map[string]any)
		for i, col := range cols {
			if b, ok := vals[i].([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = vals[i]
			}
		}
		results = append(results, row)
	}

	// A05: expose la requête exécutée
	jsonWrite(w, 200, map[string]any{
		"query":   query,
		"results": results,
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// A03 — Command Injection
// POST /api/exec  {"host":"127.0.0.1"} ou {"cmd":"id"} (si token admin forgé)
// Exploit: {"host":"127.0.0.1; cat /etc/passwd"}
// ═══════════════════════════════════════════════════════════════════════════════

func handleExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", 405)
		return
	}

	var req struct {
		Host string `json:"host"`
		Cmd  string `json:"cmd"` // réservé aux "admins"
	}
	json.NewDecoder(r.Body).Decode(&req)

	t, hasToken := bearerToken(r)
	isAdmin := hasToken && (t.Role == "admin" || t.IsAdmin)

	var out []byte
	var cmdErr error

	if isAdmin && req.Cmd != "" {
		// A03: exécution directe de commande pour les admins (token forgeable)
		out, cmdErr = exec.Command("sh", "-c", req.Cmd).CombinedOutput()
	} else {
		// A03: injection via le champ host
		// Exploit: {"host":"127.0.0.1; id; whoami"}
		out, cmdErr = exec.Command("sh", "-c",
			fmt.Sprintf("ping -c 1 %s", req.Host),
		).CombinedOutput()
	}

	errStr := ""
	if cmdErr != nil {
		errStr = cmdErr.Error()
	}
	jsonWrite(w, 200, map[string]any{
		"output": string(out),
		"error":  errStr,
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// A10 — SSRF
// POST /api/fetch  {"url":"http://169.254.169.254/latest/meta-data/"}
// Exploit: accès aux métadonnées cloud, services internes, localhost
// ═══════════════════════════════════════════════════════════════════════════════

func handleFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", 405)
		return
	}

	var req struct {
		URL string `json:"url"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.URL == "" {
		jsonErr(w, "url requis", 400)
		return
	}

	// A10: aucune validation de l'URL — accès à tout réseau interne possible
	// Essayez: http://localhost:8080/api/debug
	//          http://169.254.169.254/latest/meta-data/ (AWS)
	//          http://metadata.google.internal/ (GCP)
	//          file:///etc/passwd (selon la lib)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(req.URL)
	if err != nil {
		jsonErr(w, fmt.Sprintf("Erreur fetch: %v", err), 500)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	headers := map[string]string{}
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
	}

	jsonWrite(w, 200, map[string]any{
		"status":  resp.StatusCode,
		"headers": headers,
		"body":    string(body),
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// A05 — Security Misconfiguration : endpoint debug toujours actif, sans auth
// GET /api/debug
// ═══════════════════════════════════════════════════════════════════════════════

func handleDebug(w http.ResponseWriter, r *http.Request) {
	// A05: exposé en production, aucune authentification
	env := map[string]string{}
	for _, e := range os.Environ() {
		p := strings.SplitN(e, "=", 2)
		if len(p) == 2 {
			env[p[0]] = p[1]
		}
	}

	jsonWrite(w, 200, map[string]any{
		"app":        "VulnAPI v1.0",
		"db_path":    "/tmp/vulnapi.db",
		"env":        env, // A05: variables d'environnement exposées
		"goroutines": "non limité",
		"internals": map[string]any{
			"jwt_secret":    "supersecret123",
			"db_password":   "admin123",
			"aws_key_id":    "AKIAIOSFODNN7EXAMPLE",
			"stripe_secret": "sk_live_FAKE_KEY_DEMO",
		},
		"network": map[string]any{
			"internal_subnet": "192.168.1.0/24",
			"db_host":         "db.internal:5432",
		},
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// A01 — Path Traversal
// GET /api/files?path=../../etc/passwd
// ═══════════════════════════════════════════════════════════════════════════════

func handleFiles(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		jsonErr(w, "Paramètre 'path' requis", 400)
		return
	}

	// A01: aucune sanitisation — path traversal direct
	// Exploit: ?path=../../etc/passwd  ou  ?path=/etc/shadow
	data, err := os.ReadFile(path)
	if err != nil {
		jsonErr(w, fmt.Sprintf("Impossible de lire le fichier: %v", err), 500)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(data)
}

// ═══════════════════════════════════════════════════════════════════════════════
// A03 — XXE Pattern (Go std ne résout pas les entités externes par défaut
//        mais le pattern d'ingestion XML non validée est démontré)
// POST /api/xml  Content-Type: application/xml
// ═══════════════════════════════════════════════════════════════════════════════

func handleXML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", 405)
		return
	}

	body, _ := io.ReadAll(r.Body)

	type XMLPayload struct {
		XMLName xml.Name `xml:"data"`
		User    string   `xml:"user"`
		Action  string   `xml:"action"`
		Content string   `xml:"content"`
	}

	var payload XMLPayload
	// A03: parsing de XML utilisateur sans validation — pattern XXE
	// Dans d'autres frameworks/langages cela permettrait la lecture de fichiers locaux
	if err := xml.Unmarshal(body, &payload); err != nil {
		// A05: retourne le XML brut dans le message d'erreur
		jsonErr(w, fmt.Sprintf("Erreur XML: %v\nInput: %s", err, string(body)), 400)
		return
	}

	jsonWrite(w, 200, map[string]any{
		"parsed": payload,
		"raw":    string(body), // A05: répercute l'input utilisateur sans filtre
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// A01 — Broken Access Control : clé admin statique + token forgeable
// GET /api/admin
// Exploit header: X-Admin-Key: admin123
// Exploit token:  base64({"user_id":1,"username":"hacker","role":"admin","is_admin":true,"exp":9999999999})
// ═══════════════════════════════════════════════════════════════════════════════

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	// A01: vérification par clé statique triviale
	adminKey := r.Header.Get("X-Admin-Key")
	isAdmin := adminKey == "admin123" || adminKey == "secret" || adminKey == "true"

	// A07: ou via token forgeable
	if !isAdmin {
		if t, ok := bearerToken(r); ok && (t.Role == "admin" || t.IsAdmin) {
			isAdmin = true
		}
	}

	if !isAdmin {
		jsonErr(w, "Accès refusé", 403)
		return
	}

	// A02: dump complet incluant hashes, cartes de crédit, SSN
	rows, _ := db.Query(
		"SELECT id,username,password,email,role,is_admin,credit_card,ssn,api_key,reset_token FROM users",
	)
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		var isAdminInt int
		rows.Scan(&u.ID, &u.Username, &u.Password, &u.Email, &u.Role,
			&isAdminInt, &u.CreditCard, &u.SSN, &u.APIKey, &u.ResetToken)
		u.IsAdmin = isAdminInt == 1
		users = append(users, u)
	}

	jsonWrite(w, 200, map[string]any{
		"message": "Bienvenue admin !",
		"users":   users,
		"flag":    "FLAG{broken_access_control_a01}",
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// A03 — Server-Side Template Injection (SSTI)
// POST /api/template  {"template":"{{exec \"id\"}}","data":{}}
// ═══════════════════════════════════════════════════════════════════════════════

func handleTemplate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", 405)
		return
	}

	var req struct {
		Template string         `json:"template"`
		Data     map[string]any `json:"data"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Template == "" {
		req.Template = "Bonjour {{.Name}} !"
	}

	// A03: funcMap délibérément dangereux exposé au template utilisateur
	funcMap := template.FuncMap{
		// Exploit: {"template":"{{exec \"cat /etc/passwd\"}}"}
		"exec": func(cmd string) string {
			out, _ := exec.Command("sh", "-c", cmd).Output()
			return string(out)
		},
		// Exploit: {"template":"{{env \"HOME\"}}"}
		"env": os.Getenv,
	}

	tmpl, err := template.New("user").Funcs(funcMap).Parse(req.Template)
	if err != nil {
		jsonErr(w, fmt.Sprintf("Erreur template: %v", err), 400)
		return
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, req.Data); err != nil {
		jsonErr(w, fmt.Sprintf("Erreur exécution: %v", err), 500)
		return
	}

	jsonWrite(w, 200, map[string]any{"result": buf.String()})
}

// ═══════════════════════════════════════════════════════════════════════════════
// A07 — Token de réinitialisation prédictible + pas d'expiration
// POST /api/reset  {"username":"alice"}         → génère le token
// PUT  /api/reset  {"username":"alice","token":"...","new_password":"pwn"}
// ═══════════════════════════════════════════════════════════════════════════════

func handleReset(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		// A07: token = MD5(username + timestamp arrondi à la minute) → prévisible
		ts := time.Now().Truncate(time.Minute).Unix()
		token := md5sum(fmt.Sprintf("%s%d", req.Username, ts))

		db.Exec("UPDATE users SET reset_token=? WHERE username=?", token, req.Username)

		// A05: retourne le token directement au lieu de l'envoyer par email
		// A09: aucun log de cet événement sensible
		jsonWrite(w, 200, map[string]any{
			"message": "Token généré",
			"token":   token, // ne devrait jamais être retourné en clair
		})

	case http.MethodPut:
		var req struct {
			Username    string `json:"username"`
			Token       string `json:"token"`
			NewPassword string `json:"new_password"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		// A07: aucune vérification d'expiration du token
		row := db.QueryRow(
			"SELECT id FROM users WHERE username=? AND reset_token=?",
			req.Username, req.Token,
		)
		var id int
		if err := row.Scan(&id); err != nil {
			jsonErr(w, "Token invalide", 400)
			return
		}

		// A02: nouveau mot de passe stocké en MD5
		db.Exec("UPDATE users SET password=?, reset_token=NULL WHERE id=?",
			md5sum(req.NewPassword), id)
		jsonOK(w, "Mot de passe réinitialisé")

	default:
		http.Error(w, "Method Not Allowed", 405)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// A05 — Secrets hardcodés exposés publiquement
// GET /api/config  (aucune authentification requise)
// ═══════════════════════════════════════════════════════════════════════════════

func handleConfig(w http.ResponseWriter, r *http.Request) {
	// A01: aucune auth — config de production accessible à tous
	jsonWrite(w, 200, map[string]any{
		"database": map[string]string{
			"host":     "db.internal",
			"port":     "5432",
			"name":     "production_db",
			"user":     "dbadmin",
			"password": "Sup3rS3cr3t!Prod", // A05: credential hardcodé
		},
		"jwt": map[string]string{
			"secret":    "supersecret123",
			"algorithm": "HS256",
		},
		"aws": map[string]string{
			"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
			"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"region":            "eu-west-1",
			"s3_bucket":         "corp-backups-prod",
		},
		"smtp": map[string]string{
			"host":     "smtp.gmail.com",
			"user":     "noreply@corp.local",
			"password": "GmailAppPass123!",
		},
		"stripe": map[string]string{
			"secret_key": "sk_live_FAKE_DEMO_KEY_NOT_REAL",
		},
	})
}
