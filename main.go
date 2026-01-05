package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

const (
	dateLayout   = "2006-01-02"
	maxBodyBytes = 1 << 20
)

type server struct {
	db        *sql.DB
	jwtSecret []byte
}

type ctxKey string

const ctxKeyUserID ctxKey = "userID"

type user struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
	CreatedAt    string `json:"created_at"`
}

type expense struct {
	ID          int64  `json:"id"`
	UserID      int64  `json:"user_id"`
	Title       string `json:"title"`
	AmountCents int64  `json:"-"`
	Category    string `json:"category"`
	Date        string `json:"date"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type expenseResponse struct {
	ID        int64   `json:"id"`
	Title     string  `json:"title"`
	Amount    float64 `json:"amount"`
	Category  string  `json:"category"`
	Date      string  `json:"date"`
	CreatedAt string  `json:"created_at"`
	UpdatedAt string  `json:"updated_at"`
}

type claims struct {
	Sub int64 `json:"sub"`
	Iat int64 `json:"iat"`
	Exp int64 `json:"exp"`
}

var allowedCategories = []string{
	"Mantimentos",
	"Lazer",
	"Eletrônica",
	"Serviços públicos",
	"Roupas",
	"Saúde",
	"Outros",
}

func main() {
	port := getenv("PORT", "8080")
	dbPath := getenv("DATABASE_URL", filepath.Join("data", "expenses.db"))
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = randomSecret()
		log.Println("JWT_SECRET nao definido; usando segredo aleatorio para esta execucao")
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		log.Fatalf("criando diretorio do banco: %v", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("abrindo banco: %v", err)
	}
	defer db.Close()

	if err := initDB(db); err != nil {
		log.Fatalf("inicializando banco: %v", err)
	}

	s := &server{db: db, jwtSecret: []byte(secret)}
	mux := http.NewServeMux()
	mux.HandleFunc("/signup", s.handleSignup)
	mux.HandleFunc("/login", s.handleLogin)
	mux.Handle("/expenses", s.authMiddleware(http.HandlerFunc(s.handleExpenses)))
	mux.Handle("/expenses/", s.authMiddleware(http.HandlerFunc(s.handleExpenseByID)))

	addr := ":" + port
	log.Printf("API ouvindo em %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("servidor HTTP: %v", err)
	}
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func randomSecret() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "dev-secret"
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func initDB(db *sql.DB) error {
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		return err
	}

	schema := `
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL,
	email TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS expenses (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	title TEXT NOT NULL,
	amount_cents INTEGER NOT NULL,
	category TEXT NOT NULL,
	date TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_expenses_user_date ON expenses(user_id, date);
`

	_, err := db.Exec(schema)
	return err
}

func (s *server) handleSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}

	var req struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Name == "" || req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "name, email e password sao obrigatorios")
		return
	}

	if _, err := s.getUserByEmail(r.Context(), req.Email); err == nil {
		writeError(w, http.StatusConflict, "email ja cadastrado")
		return
	} else if !errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "erro ao verificar usuario")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "erro ao gerar senha")
		return
	}

	createdAt := time.Now().Format(time.RFC3339)
	userID, err := s.createUser(r.Context(), req.Name, req.Email, string(hash), createdAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "erro ao criar usuario")
		return
	}

	resp := user{ID: userID, Name: req.Name, Email: req.Email, CreatedAt: createdAt}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email e password sao obrigatorios")
		return
	}

	usr, err := s.getUserByEmail(r.Context(), req.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusUnauthorized, "credenciais invalidas")
			return
		}
		writeError(w, http.StatusInternalServerError, "erro ao buscar usuario")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(usr.PasswordHash), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "credenciais invalidas")
		return
	}

	token, err := s.generateToken(usr.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "erro ao gerar token")
		return
	}

	resp := map[string]any{
		"token": token,
		"user": user{ID: usr.ID, Name: usr.Name, Email: usr.Email, CreatedAt: usr.CreatedAt},
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleExpenses(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "token invalido")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleListExpenses(w, r, userID)
	case http.MethodPost:
		s.handleCreateExpense(w, r, userID)
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (s *server) handleExpenseByID(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "token invalido")
		return
	}

	expenseID, ok := parseExpenseID(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "despesa nao encontrada")
		return
	}

	switch r.Method {
	case http.MethodGet:
		exp, err := s.getExpenseByID(r.Context(), userID, expenseID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeError(w, http.StatusNotFound, "despesa nao encontrada")
				return
			}
			writeError(w, http.StatusInternalServerError, "erro ao buscar despesa")
			return
		}
		writeJSON(w, http.StatusOK, toExpenseResponse(exp))
	case http.MethodPut:
		s.handleUpdateExpense(w, r, userID, expenseID)
	case http.MethodDelete:
		if err := s.deleteExpense(r.Context(), userID, expenseID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeError(w, http.StatusNotFound, "despesa nao encontrada")
				return
			}
			writeError(w, http.StatusInternalServerError, "erro ao remover despesa")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodDelete)
	}
}

func (s *server) handleCreateExpense(w http.ResponseWriter, r *http.Request, userID int64) {
	var req expenseInput
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	exp, err := req.validateForCreate()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	exp.UserID = userID
	exp.CreatedAt = time.Now().Format(time.RFC3339)
	exp.UpdatedAt = exp.CreatedAt

	id, err := s.createExpense(r.Context(), exp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "erro ao criar despesa")
		return
	}
	exp.ID = id
	writeJSON(w, http.StatusCreated, toExpenseResponse(exp))
}

func (s *server) handleUpdateExpense(w http.ResponseWriter, r *http.Request, userID, expenseID int64) {
	current, err := s.getExpenseByID(r.Context(), userID, expenseID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "despesa nao encontrada")
			return
		}
		writeError(w, http.StatusInternalServerError, "erro ao buscar despesa")
		return
	}

	var req expenseInput
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	updated, err := req.applyUpdate(current)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated.UpdatedAt = time.Now().Format(time.RFC3339)

	if err := s.updateExpense(r.Context(), updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "despesa nao encontrada")
			return
		}
		writeError(w, http.StatusInternalServerError, "erro ao atualizar despesa")
		return
	}

	writeJSON(w, http.StatusOK, toExpenseResponse(updated))
}

func (s *server) handleListExpenses(w http.ResponseWriter, r *http.Request, userID int64) {
	filter := r.URL.Query().Get("filter")
	startDate, endDate, err := resolveDateRange(filter, r.URL.Query().Get("start"), r.URL.Query().Get("end"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	expenses, err := s.listExpenses(r.Context(), userID, startDate, endDate)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "erro ao listar despesas")
		return
	}

	resp := make([]expenseResponse, 0, len(expenses))
	for _, exp := range expenses {
		resp = append(resp, toExpenseResponse(exp))
	}
	writeJSON(w, http.StatusOK, resp)
}

type expenseInput struct {
	Title    *string  `json:"title"`
	Amount   *float64 `json:"amount"`
	Category *string  `json:"category"`
	Date     *string  `json:"date"`
}

func (in expenseInput) validateForCreate() (expense, error) {
	if in.Title == nil || in.Amount == nil || in.Category == nil {
		return expense{}, errors.New("title, amount e category sao obrigatorios")
	}
	base := expense{Date: time.Now().Format(dateLayout)}
	return in.applyUpdate(base)
}

func (in expenseInput) applyUpdate(current expense) (expense, error) {
	updated := current
	if in.Title != nil {
		updated.Title = strings.TrimSpace(*in.Title)
		if updated.Title == "" {
			return expense{}, errors.New("title nao pode ser vazio")
		}
	}
	if in.Amount != nil {
		cents, err := amountToCents(*in.Amount)
		if err != nil {
			return expense{}, err
		}
		updated.AmountCents = cents
	}
	if in.Category != nil {
		cat := strings.TrimSpace(*in.Category)
		validated, ok := normalizeCategory(cat)
		if !ok {
			return expense{}, errors.New("categoria invalida")
		}
		updated.Category = validated
	}
	if in.Date != nil {
		date := strings.TrimSpace(*in.Date)
		if date == "" {
			return expense{}, errors.New("date nao pode ser vazio")
		}
		parsed, err := parseDate(date)
		if err != nil {
			return expense{}, err
		}
		updated.Date = parsed.Format(dateLayout)
	}

	if updated.Title == "" || updated.Category == "" || updated.Date == "" || updated.AmountCents == 0 {
		return expense{}, errors.New("title, amount, category e date sao obrigatorios")
	}

	return updated, nil
}

func normalizeCategory(input string) (string, bool) {
	for _, allowed := range allowedCategories {
		if strings.EqualFold(input, allowed) {
			return allowed, true
		}
	}
	return "", false
}

func parseDate(value string) (time.Time, error) {
	parsed, err := time.ParseInLocation(dateLayout, value, time.Local)
	if err != nil {
		return time.Time{}, errors.New("date deve estar no formato YYYY-MM-DD")
	}
	return parsed, nil
}

func amountToCents(amount float64) (int64, error) {
	if amount <= 0 {
		return 0, errors.New("amount deve ser maior que zero")
	}
	if math.IsNaN(amount) || math.IsInf(amount, 0) {
		return 0, errors.New("amount invalido")
	}
	cents := int64(math.Round(amount * 100))
	if cents <= 0 {
		return 0, errors.New("amount deve ser maior que zero")
	}
	return cents, nil
}

func toExpenseResponse(exp expense) expenseResponse {
	return expenseResponse{
		ID:        exp.ID,
		Title:     exp.Title,
		Amount:    float64(exp.AmountCents) / 100,
		Category:  exp.Category,
		Date:      exp.Date,
		CreatedAt: exp.CreatedAt,
		UpdatedAt: exp.UpdatedAt,
	}
}

func resolveDateRange(filter, startValue, endValue string) (string, string, error) {
	if filter == "" {
		return "", "", nil
	}

	today := time.Now().In(time.Local)
	today = time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, today.Location())

	switch filter {
	case "last_week":
		start := today.AddDate(0, 0, -7)
		return start.Format(dateLayout), today.Format(dateLayout), nil
	case "last_month":
		start := today.AddDate(0, -1, 0)
		return start.Format(dateLayout), today.Format(dateLayout), nil
	case "last_3_months":
		start := today.AddDate(0, -3, 0)
		return start.Format(dateLayout), today.Format(dateLayout), nil
	case "custom":
		if startValue == "" || endValue == "" {
			return "", "", errors.New("start e end sao obrigatorios para filtro custom")
		}
		start, err := parseDate(startValue)
		if err != nil {
			return "", "", err
		}
		end, err := parseDate(endValue)
		if err != nil {
			return "", "", err
		}
		if end.Before(start) {
			return "", "", errors.New("end nao pode ser menor que start")
		}
		return start.Format(dateLayout), end.Format(dateLayout), nil
	default:
		return "", "", errors.New("filtro invalido")
	}
}

func (s *server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "token ausente")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		claims, err := s.parseToken(token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "token invalido")
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyUserID, claims.Sub)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *server) generateToken(userID int64) (string, error) {
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	now := time.Now().Unix()
	payload := claims{Sub: userID, Iat: now, Exp: now + int64((7 * 24 * time.Hour).Seconds())}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	headerEnc := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadEnc := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerEnc + "." + payloadEnc
	signature := signHS256(signingInput, s.jwtSecret)
	return signingInput + "." + signature, nil
}

func (s *server) parseToken(token string) (claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims{}, errors.New("token malformado")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims{}, errors.New("payload invalido")
	}

	signingInput := parts[0] + "." + parts[1]
	expected := signHS256(signingInput, s.jwtSecret)
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return claims{}, errors.New("assinatura invalida")
	}

	var c claims
	if err := json.Unmarshal(payloadBytes, &c); err != nil {
		return claims{}, errors.New("payload invalido")
	}
	if c.Sub == 0 {
		return claims{}, errors.New("usuario invalido")
	}
	if time.Now().Unix() > c.Exp {
		return claims{}, errors.New("token expirado")
	}
	return c, nil
}

func signHS256(input string, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	_, _ = h.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func userIDFromContext(ctx context.Context) (int64, bool) {
	value := ctx.Value(ctxKeyUserID)
	if value == nil {
		return 0, false
	}
	id, ok := value.(int64)
	return id, ok
}

func parseExpenseID(path string) (int64, bool) {
	if !strings.HasPrefix(path, "/expenses/") {
		return 0, false
	}
	idStr := strings.TrimPrefix(path, "/expenses/")
	if idStr == "" || strings.Contains(idStr, "/") {
		return 0, false
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("corpo deve conter um unico objeto JSON")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		_ = json.NewEncoder(w).Encode(data)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func methodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeError(w, http.StatusMethodNotAllowed, "metodo nao permitido")
}

func (s *server) createUser(ctx context.Context, name, email, passwordHash, createdAt string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO users (name, email, password_hash, created_at)
		VALUES (?, ?, ?, ?)
	`, name, email, passwordHash, createdAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *server) getUserByEmail(ctx context.Context, email string) (user, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, email, password_hash, created_at
		FROM users
		WHERE email = ?
	`, email)

	var usr user
	if err := row.Scan(&usr.ID, &usr.Name, &usr.Email, &usr.PasswordHash, &usr.CreatedAt); err != nil {
		return user{}, err
	}
	return usr, nil
}

func (s *server) createExpense(ctx context.Context, exp expense) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO expenses (user_id, title, amount_cents, category, date, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, exp.UserID, exp.Title, exp.AmountCents, exp.Category, exp.Date, exp.CreatedAt, exp.UpdatedAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *server) listExpenses(ctx context.Context, userID int64, startDate, endDate string) ([]expense, error) {
	query := `
		SELECT id, user_id, title, amount_cents, category, date, created_at, updated_at
		FROM expenses
		WHERE user_id = ?
	`
	args := []any{userID}
	if startDate != "" && endDate != "" {
		query += " AND date >= ? AND date <= ?"
		args = append(args, startDate, endDate)
	}
	query += " ORDER BY date DESC, id DESC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var expenses []expense
	for rows.Next() {
		var exp expense
		if err := rows.Scan(&exp.ID, &exp.UserID, &exp.Title, &exp.AmountCents, &exp.Category, &exp.Date, &exp.CreatedAt, &exp.UpdatedAt); err != nil {
			return nil, err
		}
		expenses = append(expenses, exp)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return expenses, nil
}

func (s *server) getExpenseByID(ctx context.Context, userID, expenseID int64) (expense, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, title, amount_cents, category, date, created_at, updated_at
		FROM expenses
		WHERE id = ? AND user_id = ?
	`, expenseID, userID)

	var exp expense
	if err := row.Scan(&exp.ID, &exp.UserID, &exp.Title, &exp.AmountCents, &exp.Category, &exp.Date, &exp.CreatedAt, &exp.UpdatedAt); err != nil {
		return expense{}, err
	}
	return exp, nil
}

func (s *server) updateExpense(ctx context.Context, exp expense) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE expenses
		SET title = ?, amount_cents = ?, category = ?, date = ?, updated_at = ?
		WHERE id = ? AND user_id = ?
	`, exp.Title, exp.AmountCents, exp.Category, exp.Date, exp.UpdatedAt, exp.ID, exp.UserID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *server) deleteExpense(ctx context.Context, userID, expenseID int64) error {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM expenses
		WHERE id = ? AND user_id = ?
	`, expenseID, userID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}
