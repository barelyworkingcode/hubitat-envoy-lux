#!/bin/bash

# Fixed Enphase OAuth Authentication Script
# Now implements the complete JavaScript flow from the callback

set -e

# Configuration
ENPHASE_USERNAME="${ENPHASE_USERNAME}"
ENPHASE_PASSWORD="${ENPHASE_PASSWORD}"
ENVOY_HOST="${ENVOY_HOST:-envoy.lan}"

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# URL encode function
urlencode() {
    local string="$1"
    local strlen=${#string}
    local encoded=""
    local pos c o

    for (( pos=0 ; pos<strlen ; pos++ )); do
        c=${string:$pos:1}
        case "$c" in
            [-_.~a-zA-Z0-9] ) o="${c}" ;;
            * ) printf -v o '%%%02x' "'$c" ;;
        esac
        encoded+="${o}"
    done
    echo "${encoded}"
}

# Function to generate random string for code_verifier
generate_code_verifier() {
    openssl rand -base64 48 | tr -d "=+/" | cut -c1-64
}

# Function to generate code_challenge from code_verifier
generate_code_challenge() {
    local code_verifier="$1"
    echo -n "$code_verifier" | openssl dgst -sha256 -binary | openssl base64 | tr -d "=" | tr '+/' '-_'
}

# Function to extract value from HTML form
extract_form_value() {
    local html="$1"
    local field_name="$2"
    echo "$html" | grep -o "name=[\"']${field_name}[\"'][^>]*value=[\"'][^\"']*[\"']" | sed "s/.*value=[\"']\([^\"']*\)[\"'].*/\1/" | head -1
}

# Function to extract Location header
extract_location() {
    local headers="$1"
    echo "$headers" | grep -i "^location:" | sed 's/location: *//i' | tr -d '\r'
}

# Function to extract query parameter from URL
extract_query_param() {
    local url="$1"
    local param="$2"
    echo "$url" | sed -n "s/.*[?&]${param}=\([^&]*\).*/\1/p"
}

# Function to extract Set-Cookie value
extract_cookie() {
    local headers="$1"
    local cookie_name="$2"
    echo "$headers" | grep -i "set-cookie:" | grep "${cookie_name}=" | sed "s/.*${cookie_name}=\([^;]*\).*/\1/" | head -1
}

main() {
    log "Starting complete Enphase OAuth authentication flow..."

    TEMP_DIR=$(mktemp -d)
    COOKIE_JAR="$TEMP_DIR/cookies.txt"

    cleanup() {
        rm -rf "$TEMP_DIR"
    }
    trap cleanup EXIT

    # Step 1: Generate PKCE parameters
    log "Step 1: Generating PKCE parameters..."
    CODE_VERIFIER=$(generate_code_verifier)
    CODE_CHALLENGE=$(generate_code_challenge "$CODE_VERIFIER")

    log "Code Verifier: $CODE_VERIFIER"
    log "Code Challenge: $CODE_CHALLENGE"

    # Step 2: Build authorization URL
    CLIENT_ID="envoy-ui-client"
    REDIRECT_URI="https://${ENVOY_HOST}/auth/callback"
    SCOPE="482515006477"

    AUTH_URL="https://entrez.enphaseenergy.com/authorize"
    AUTH_URL+="?code_challenge=$(urlencode "$CODE_CHALLENGE")"
    AUTH_URL+="&client_id=$(urlencode "$CLIENT_ID")"
    AUTH_URL+="&redirect_uri=$(urlencode "$REDIRECT_URI")"
    AUTH_URL+="&scope=$(urlencode "$SCOPE")"
    AUTH_URL+="&response_type=code"
    AUTH_URL+="&code_challenge_method=S256"

    # Step 3: Get login page
    log "Step 2: Fetching login page..."
    LOGIN_RESPONSE=$(curl -s -k \
        -c "$COOKIE_JAR" \
        -D "$TEMP_DIR/login_headers.txt" \
        -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" \
        "$AUTH_URL")

    if [ $? -ne 0 ]; then
        error "Failed to fetch login page"
        exit 1
    fi

    # Step 4: Extract form data
    log "Step 3: Parsing login form..."
    CSRF_TOKEN=$(extract_form_value "$LOGIN_RESPONSE" "_csrf")
    FORM_CODE_CHALLENGE=$(extract_form_value "$LOGIN_RESPONSE" "codeChallenge")
    FORM_REDIRECT_URI=$(extract_form_value "$LOGIN_RESPONSE" "redirectUri")
    FORM_CLIENT=$(extract_form_value "$LOGIN_RESPONSE" "client")
    FORM_CLIENT_ID=$(extract_form_value "$LOGIN_RESPONSE" "clientId")
    FORM_AUTH_FLOW=$(extract_form_value "$LOGIN_RESPONSE" "authFlow")
    FORM_SERIAL_NUM=$(extract_form_value "$LOGIN_RESPONSE" "serialNum")
    FORM_GRANT_TYPE=$(extract_form_value "$LOGIN_RESPONSE" "grantType")
    FORM_STATE=$(extract_form_value "$LOGIN_RESPONSE" "state")
    FORM_INVALID_SERIAL=$(extract_form_value "$LOGIN_RESPONSE" "invalidSerialNum")

    # Step 5: Submit login credentials
    log "Step 4: Submitting login credentials..."

    # Prepare POST data
    POST_DATA="username=$(urlencode "$ENPHASE_USERNAME")"
    POST_DATA+="&password=$(urlencode "$ENPHASE_PASSWORD")"
    POST_DATA+="&_csrf=$(urlencode "$CSRF_TOKEN")"
    POST_DATA+="&codeChallenge=$(urlencode "$FORM_CODE_CHALLENGE")"
    POST_DATA+="&redirectUri=$(urlencode "$FORM_REDIRECT_URI")"
    POST_DATA+="&client=$(urlencode "$FORM_CLIENT")"
    POST_DATA+="&clientId=$(urlencode "$FORM_CLIENT_ID")"
    POST_DATA+="&authFlow=$(urlencode "$FORM_AUTH_FLOW")"
    POST_DATA+="&serialNum=$(urlencode "$FORM_SERIAL_NUM")"
    POST_DATA+="&grantType=$(urlencode "$FORM_GRANT_TYPE")"
    POST_DATA+="&state=$(urlencode "$FORM_STATE")"
    POST_DATA+="&invalidSerialNum=$(urlencode "$FORM_INVALID_SERIAL")"

    # Submit login form
    curl -s -k \
        -b "$COOKIE_JAR" \
        -c "$COOKIE_JAR" \
        -D "$TEMP_DIR/login_submit_headers.txt" \
        -o "$TEMP_DIR/login_submit_response.html" \
        -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Referer: $AUTH_URL" \
        -X POST \
        --data "$POST_DATA" \
        "https://entrez.enphaseenergy.com/login"

    # Step 6: Extract authorization code
    log "Step 5: Extracting authorization code..."
    LOCATION=$(extract_location "$(cat "$TEMP_DIR/login_submit_headers.txt")")

    if [[ "$LOCATION" == *"${ENVOY_HOST}/auth/callback"* ]]; then
        AUTH_CODE=$(extract_query_param "$LOCATION" "code")
        if [ -n "$AUTH_CODE" ]; then
            success "Authorization code obtained: $AUTH_CODE"
        else
            error "No authorization code found in callback URL"
            exit 1
        fi
    else
        error "No callback redirect found"
        exit 1
    fi

    # Step 7: Exchange authorization code for JWT
    log "Step 6: Exchanging code for JWT token..."

    JWT_PAYLOAD=$(cat <<EOF
{
    "client_id": "envoy-ui-1",
    "grant_type": "authorization_code",
    "redirect_uri": "$REDIRECT_URI",
    "code_verifier": "$CODE_VERIFIER",
    "code": "$AUTH_CODE"
}
EOF
)

    JWT_RESPONSE=$(curl -s -k \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -X POST \
        --data "$JWT_PAYLOAD" \
        "https://${ENVOY_HOST}/auth/get_jwt")

    if [ $? -ne 0 ]; then
        error "Failed to exchange code for JWT"
        exit 1
    fi

    # Extract access token from JSON response
    ACCESS_TOKEN=$(echo "$JWT_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)

    if [ -z "$ACCESS_TOKEN" ]; then
        # Fallback to grep if python fails
        ACCESS_TOKEN=$(echo "$JWT_RESPONSE" | grep -o '"access_token":"[^"]*"' | sed 's/"access_token":"//;s/"//')

        if [ -z "$ACCESS_TOKEN" ]; then
            error "Failed to extract access token from response"
            log "JWT Response: $JWT_RESPONSE"
            exit 1
        fi
    fi

    success "JWT access token obtained: ${ACCESS_TOKEN:0:20}..."

    # Step 8: Exchange JWT for session cookie
    log "Step 7: Exchanging JWT for session cookie..."

    curl -s -k \
        -b "$COOKIE_JAR" \
        -c "$COOKIE_JAR" \
        -D "$TEMP_DIR/check_jwt_headers.txt" \
        -o "$TEMP_DIR/check_jwt_response.txt" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -X POST \
        "https://${ENVOY_HOST}/auth/check_jwt"

    # Extract session ID from cookies
    SESSION_ID=$(extract_cookie "$(cat "$TEMP_DIR/check_jwt_headers.txt")" "sessionId")

    # Also check cookie jar
    if [ -z "$SESSION_ID" ] && [ -f "$COOKIE_JAR" ]; then
        SESSION_ID=$(grep "sessionId" "$COOKIE_JAR" | cut -f7 | head -1)
    fi

    if [ -n "$SESSION_ID" ]; then
        success "Session ID obtained: $SESSION_ID"
    else
        error "Failed to obtain session ID"
        log "Check JWT headers saved to: $TEMP_DIR/check_jwt_headers.txt"
        log "Check JWT response saved to: $TEMP_DIR/check_jwt_response.txt"
        exit 1
    fi

    # Step 9: Test access to production.json
    log "Step 8: Testing access to production.json..."

    PRODUCTION_RESPONSE=$(curl -s -k \
        -H "Cookie: sessionId=$SESSION_ID" \
        -H "User-Agent: curl/7.68.0" \
        -w "%{http_code}" \
        "https://${ENVOY_HOST}/production.json")

    HTTP_CODE="${PRODUCTION_RESPONSE: -3}"
    RESPONSE_BODY="${PRODUCTION_RESPONSE%???}"

    if [ "$HTTP_CODE" = "200" ]; then
        success "Successfully accessed production.json!"
        echo
        echo "=== SESSION ID ==="
        echo "$SESSION_ID"
        echo
        echo "=== PRODUCTION DATA ==="
        echo "$RESPONSE_BODY" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE_BODY"
        echo

        # Save session ID to file for future use
        echo "$SESSION_ID" > session_id.txt
        success "Session ID saved to session_id.txt"

    else
        error "Failed to access production.json. HTTP Code: $HTTP_CODE"
        echo "Response: $RESPONSE_BODY"
        exit 1
    fi

    log "Complete authentication flow successful!"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi