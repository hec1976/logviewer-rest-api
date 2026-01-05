#!/usr/bin/env bash
set -euo pipefail

# Mini-Checksuite fuer Log-Viewer REST-API
# - testet Root, logdirs, loglisting, logfile tail
# - testet OPTIONS/CORS
# - testet Fehlerfaelle (404, Traversal)
# - testet optional Token-Case (wenn API_TOKEN gesetzt ist)

BASE_URL="${1:-http://127.0.0.1:5005}"
TOKEN_HEADER="${TOKEN_HEADER:-}"   # z.B. export TOKEN_HEADER="X-API-Token: geheim"
CURL_BIN="${CURL_BIN:-curl}"

# Pretty helper
hr() { printf "\n== %s ==\n" "$*"; }

req() {
  local method="$1"; shift
  local url="$1"; shift
  local extra_args=("$@")

  # -sS: still show errors, -D-: headers to stdout, -o: body temp
  local body_tmp
  body_tmp="$(mktemp)"
  local hdr_tmp
  hdr_tmp="$(mktemp)"

  # Token Header optional (wenn gesetzt)
  local token_args=()
  if [[ -n "${TOKEN_HEADER}" ]]; then
    token_args=(-H "${TOKEN_HEADER}")
  fi

  # shellcheck disable=SC2086
  set +e
  "${CURL_BIN}" -sS -k -X "${method}" \
    -D "${hdr_tmp}" \
    "${token_args[@]}" \
    "${extra_args[@]}" \
    -o "${body_tmp}" \
    "${url}"
  local rc=$?
  set -e

  # Statuscode aus Header ziehen
  local status
  status="$(awk 'BEGIN{code=0} /^HTTP\/ /{code=$2} END{print code}' "${hdr_tmp}")"

  echo "URL: ${url}"
  echo "HTTP: ${status} (curl-rc=${rc})"

  echo "--- Response headers (relevant) ---"
  grep -iE '^(HTTP/|content-type:|cache-control:|access-control-allow-)' "${hdr_tmp}" || true

  echo "--- Body (first 400 chars) ---"
  head -c 400 "${body_tmp}"
  echo
  echo "---"

  rm -f "${body_tmp}" "${hdr_tmp}"

  # return nonzero wenn curl kaputt ist (kein HTTP Fehler, sondern Transport)
  if [[ ${rc} -ne 0 ]]; then
    return ${rc}
  fi
  return 0
}

hr "1) Root (Endpoints Liste)"
req GET "${BASE_URL}/"

hr "2) OPTIONS (CORS Preflight)"
req OPTIONS "${BASE_URL}/anything" -H "Origin: https://example.org" -H "Access-Control-Request-Method: GET"

hr "3) /logdirs"
req GET "${BASE_URL}/logdirs"

# Namen von erstem logdir aus /logdirs extrahieren (ohne jq)
hr "4) Ersten Logdir-Namen ermitteln"
LOGDIR_NAME="$("${CURL_BIN}" -sS -k "${BASE_URL}/logdirs" \
  ${TOKEN_HEADER:+-H "$TOKEN_HEADER"} \
  | perl -0777 -ne 'if (/"logdirs"\s*:\s*\[\s*\{\s*"name"\s*:\s*"([^"]+)"/) { print $1 }')"

if [[ -z "${LOGDIR_NAME}" ]]; then
  echo "Konnte keinen logdir-Namen finden. Abbruch (bitte Config logdirs pruefen)."
  exit 2
fi
echo "Erster logdir: ${LOGDIR_NAME}"

hr "5) /log/:name (File listing)"
req GET "${BASE_URL}/log/${LOGDIR_NAME}"

# Erste Datei aus listing ziehen
hr "6) Erste Datei aus Listing ermitteln"
FIRST_FILE="$("${CURL_BIN}" -sS -k "${BASE_URL}/log/${LOGDIR_NAME}" \
  ${TOKEN_HEADER:+-H "$TOKEN_HEADER"} \
  | perl -0777 -ne 'if (/"files"\s*:\s*\[\s*"([^"]+)"/) { print $1 }')"

if [[ -z "${FIRST_FILE}" ]]; then
  echo "Keine Datei gefunden im Logdir ${LOGDIR_NAME}. (Das ist okay, dann werden File-Tests uebersprungen.)"
else
  echo "Erste Datei: ${FIRST_FILE}"

  hr "7) /log/*name/*file (tail default lines)"
  req GET "${BASE_URL}/log/${LOGDIR_NAME}/${FIRST_FILE}"

  hr "8) /log/*name/*file?lines=50"
  req GET "${BASE_URL}/log/${LOGDIR_NAME}/${FIRST_FILE}?lines=50"

  hr "9) /log/*name/*file?lines=5 (clamp -> 10)"
  req GET "${BASE_URL}/log/${LOGDIR_NAME}/${FIRST_FILE}?lines=5"

  hr "10) /log/*name/*file?lines=999999 (clamp -> 50000)"
  req GET "${BASE_URL}/log/${LOGDIR_NAME}/${FIRST_FILE}?lines=999999"
fi

hr "11) Fehlerfall: Unbekanntes Logverzeichnis (404 JSON)"
req GET "${BASE_URL}/log/___does_not_exist___"

hr "12) Fehlerfall: Unbekannte Route (404 JSON)"
req GET "${BASE_URL}/___nope___"

hr "13) Fehlerfall: Directory Traversal (400 JSON)"
req GET "${BASE_URL}/log/${LOGDIR_NAME}/../etc/passwd"

echo
echo "FERTIG. Wenn ACL oder Token greift, kannst du bei 401/403 sehen, ob es wie erwartet arbeitet."
echo "Tipp: fuer Token Test export TOKEN_HEADER='X-API-Token: DEIN_TOKEN' setzen."
