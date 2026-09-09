#!/bin/bash
# iter32 backend regression checks
BASE=$(grep REACT_APP_BACKEND_URL /app/frontend/.env | cut -d= -f2 | tr -d '"' | tr -d "'")
TOKEN=$(curl -s -X POST "$BASE/api/auth/login" -H "Content-Type: application/json" -d '{"email":"admin@nivxray.com","password":"uulVDp5cCSB3Hva99s7UUAwK"}' | python -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")
export BASE TOKEN
echo "=== TOKEN_LEN=${#TOKEN} ==="
