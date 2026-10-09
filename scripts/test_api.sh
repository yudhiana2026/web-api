#!/usr/bin/env bash
set -e

BASE_URL="http://localhost:8080"
COOKIE_JAR="cookies.txt"

# Warna teks untuk terminal
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}  Pengujian Langsung API (Authentication & CSRF Flow)  ${NC}"
echo -e "${BLUE}======================================================${NC}"

# Bersihkan file cookie lama jika ada
rm -f "$COOKIE_JAR" old_cookies.txt

echo -e "\n${YELLOW}[1] Mendaftarkan Pengguna Baru (/api/auth/register)...${NC}"
REG_RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "Password123!",
    "display_name": "Budi Santoso",
    "role": "user"
  }')
echo "$REG_RESP"

echo -e "\n${YELLOW}[2] Melakukan Login & Menyimpan Cookies (/api/auth/login)...${NC}"
LOGIN_RESP=$(curl -s -i -c "$COOKIE_JAR" -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "Password123!"
  }')
echo "$LOGIN_RESP" | head -n 25

# Simpan salinan cookie awal untuk pengujian reuse attack nanti
cp "$COOKIE_JAR" old_cookies.txt

echo -e "\n${GREEN}Isi Cookies yang diterima dari Server (Set-Cookie):${NC}"
cat "$COOKIE_JAR"

# Ambil token CSRF dari cookie jar
CSRF_TOKEN=$(grep "csrf_token" "$COOKIE_JAR" | awk '{print $7}')
echo -e "\n${GREEN}Extracted CSRF Token:${NC} $CSRF_TOKEN"

echo -e "\n${YELLOW}[3] Mengakses Endpoint Terproteksi (GET /api/user/profile) dengan Cookie...${NC}"
PROFILE_RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -b "$COOKIE_JAR" "$BASE_URL/api/user/profile")
echo "$PROFILE_RESP"

echo -e "\n${YELLOW}[4] Uji Coba Mutasi Data TANPA Header CSRF (Harus Ditolak 403)...${NC}"
FAIL_CSRF_RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -b "$COOKIE_JAR" -X PUT "$BASE_URL/api/user/profile" \
  -H "Content-Type: application/json" \
  -d '{"display_name": "Peretas Tanpa CSRF"}')
echo "$FAIL_CSRF_RESP"

echo -e "\n${YELLOW}[5] Uji Coba Mutasi Data DENGAN Header X-CSRF-Token yang Valid (Harus 200 OK)...${NC}"
OK_CSRF_RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -b "$COOKIE_JAR" -X PUT "$BASE_URL/api/user/profile" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -d '{"display_name": "Budi Santoso Terupdate"}')
echo "$OK_CSRF_RESP"

echo -e "\n${YELLOW}[6] Uji Coba Refresh Token Rotation (/api/auth/refresh)...${NC}"
REFRESH_RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -b "$COOKIE_JAR" -c "$COOKIE_JAR" -X POST "$BASE_URL/api/auth/refresh" \
  -H "X-CSRF-Token: $CSRF_TOKEN")
echo "$REFRESH_RESP"

NEW_CSRF_TOKEN=$(grep "csrf_token" "$COOKIE_JAR" | awk '{print $7}')
echo -e "\n${GREEN}Cookies setelah Refresh Token Rotation (Token Baru Diterbitkan):${NC}"
cat "$COOKIE_JAR"

echo -e "\n${RED}[7] Uji Coba Serangan REUSE ATTACK (Mengirim Token Lama yang Sudah Dirotasi)...${NC}"
REUSE_RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -b "old_cookies.txt" -X POST "$BASE_URL/api/auth/refresh" \
  -H "X-CSRF-Token: $CSRF_TOKEN")
echo "$REUSE_RESP"

echo -e "\n${YELLOW}[8] Uji Coba Logout (/api/auth/logout)...${NC}"
LOGOUT_RESP=$(curl -s -i -b "$COOKIE_JAR" -c "$COOKIE_JAR" -X POST "$BASE_URL/api/auth/logout" \
  -H "X-CSRF-Token: $NEW_CSRF_TOKEN")
echo "$LOGOUT_RESP" | head -n 25

echo -e "\n${GREEN}Status Cookies setelah Logout (Max-Age=-1 / Terhapus):${NC}"
cat "$COOKIE_JAR"

# Bersihkan file sementara
rm -f old_cookies.txt

echo -e "\n${BLUE}======================================================${NC}"
echo -e "${GREEN}  Semua Skenario Pengujian Berhasil Dijalankan!         ${NC}"
echo -e "${BLUE}======================================================${NC}"
