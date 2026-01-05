# API de rastreamento de despesas

API simples para cadastro de usuários, autenticação com JWT e CRUD de despesas por usuário.

## Recursos

- Cadastro e login de usuários.
- JWT para autenticar as rotas protegidas.
- CRUD de despesas (criar, listar, atualizar e remover).
- Filtros por intervalo de datas (semana passada, mês passado, últimos 3 meses e personalizado).

## Tecnologias

- Go
- SQLite (driver `github.com/mattn/go-sqlite3`)

> Observação: o driver `go-sqlite3` exige CGO habilitado.

## Como rodar

1) Defina as variáveis de ambiente (opcionais):

```bash
export PORT=8080
export DATABASE_URL=./data/expenses.db
export JWT_SECRET=uma-chave-secreta
```

> Se `JWT_SECRET` não for definido, a API gera um segredo aleatório a cada execução.

2) Suba a API:

```bash
go run ./...
```

A API ficará disponível em `http://localhost:8080`.

## Endpoints

### Autenticação

- `POST /signup`

```json
{
  "name": "Maria",
  "email": "maria@email.com",
  "password": "123456"
}
```

- `POST /login`

```json
{
  "email": "maria@email.com",
  "password": "123456"
}
```

Resposta:

```json
{
  "token": "JWT_AQUI",
  "user": {
    "id": 1,
    "name": "Maria",
    "email": "maria@email.com",
    "created_at": "2024-01-01T00:00:00Z"
  }
}
```

### Despesas (rotas protegidas)

Use o header `Authorization: Bearer <token>`.

- `GET /expenses`

Filtros disponíveis (query string):

- `filter=last_week`
- `filter=last_month`
- `filter=last_3_months`
- `filter=custom&start=YYYY-MM-DD&end=YYYY-MM-DD`

Exemplo:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/expenses?filter=custom&start=2024-01-01&end=2024-01-31"
```

- `POST /expenses`

```json
{
  "title": "Supermercado",
  "amount": 150.75,
  "category": "Mantimentos",
  "date": "2024-01-15"
}
```

> Se `date` não for informado, a API usa a data de hoje.

- `GET /expenses/{id}`
- `PUT /expenses/{id}`

```json
{
  "title": "Supermercado",
  "amount": 160.00,
  "category": "Mantimentos",
  "date": "2024-01-15"
}
```

> O `PUT` aceita atualização parcial. Campos omitidos permanecem iguais.

- `DELETE /expenses/{id}`

## Categorias aceitas

- Mantimentos
- Lazer
- Eletrônica
- Serviços públicos
- Roupas
- Saúde
- Outros

A API valida a categoria enviada e guarda o valor canônico.

## Estrutura do projeto

- `main.go` - servidor HTTP, handlers, autenticação e acesso ao banco.
- `go.mod` - dependências.
