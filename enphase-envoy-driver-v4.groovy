/**
 *  Enphase Envoy Solar Power Monitor v4 - With Complete OAuth Auto-Authentication
 *
 *  This driver implements the complete Enphase OAuth + PKCE authentication flow
 *  discovered through reverse engineering. It intelligently manages session cookies
 *  and only re-authenticates when necessary (typically every 24-48 hours).
 *
 *  Copyright 2025
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 *  for the specific language governing permissions and limitations under the License.
 */

import groovy.json.JsonSlurper
import groovy.json.JsonBuilder
import java.security.MessageDigest

metadata {
    definition (name: "Enphase Envoy Solar Monitor v4", namespace: "custom", author: "Custom", importUrl: "") {
        capability "PowerMeter"
        capability "EnergyMeter"
        capability "Sensor"
        capability "Refresh"

        attribute "solarProduction", "number"
        attribute "homeConsumption", "number"
        attribute "netConsumption", "number"
        attribute "exportPower", "number"
        attribute "lastUpdated", "string"
        attribute "authStatus", "string"
        attribute "sessionExpiry", "string"
        attribute "lastAuthTime", "string"
        attribute "authAttempts", "number"

        command "refresh"
        command "authenticate"
        command "clearSession"
        command "createChildDevices"
        command "deleteChildDevices"
    }

    preferences {
        input "envoyIP", "text", title: "Envoy IP Address", description: "IP address of your Enphase Envoy (default: envoy.lan)", defaultValue: "envoy.lan", required: true
        input "enphaseUsername", "text", title: "Enphase Username", description: "Your Enphase account username/email", required: true
        input "enphasePassword", "password", title: "Enphase Password", description: "Your Enphase account password", required: true
        input "pollInterval", "number", title: "Poll Interval (minutes)", description: "How often to update data", defaultValue: 5, range: "1..60", required: true
        input "scaleFactor", "number", title: "Scale Factor", description: "Divide lux values by this amount", defaultValue: 1000, required: true
        input "sessionDuration", "number", title: "Session Duration (hours)", description: "How long to assume session is valid", defaultValue: 24, range: "1..72", required: true
        input "manualSessionId", "text", title: "Manual Session ID (Optional)", description: "Use this session ID instead of auto-authentication", required: false
        input "envoySerial", "text", title: "Envoy Serial Number (Optional)", description: "Device serial number - if not provided, will be auto-detected from device", required: false
        input "logEnable", "bool", title: "Enable debug logging", defaultValue: true
        input "logAuth", "bool", title: "Enable authentication logging", defaultValue: true
    }
}

def installed() {
    log.info "Enphase Envoy Solar Monitor v4 installed"
    initialize()
    createChildDevices()
}

def updated() {
    log.info "Enphase Envoy Solar Monitor v4 updated"
    unschedule()

    // Clear cached session on config change to force re-authentication
    state.sessionId = null
    state.sessionExpiry = null
    state.lastAuthTime = null
    state.authAttempts = 0

    if (logEnable) log.debug "Cleared cached session data due to configuration update"

    sendEvent(name: "authStatus", value: "Configuration Updated")
    sendEvent(name: "sessionExpiry", value: "Unknown")
    sendEvent(name: "lastAuthTime", value: "Never")
    sendEvent(name: "authAttempts", value: 0)

    initialize()
}

def initialize() {
    log.info "Initializing Enphase Envoy Solar Monitor v4 with OAuth authentication"

    // Initialize state variables if not present
    if (!state.authAttempts) state.authAttempts = 0
    if (!state.sessionId) state.sessionId = null
    if (!state.sessionExpiry) state.sessionExpiry = null
    if (!state.lastAuthTime) state.lastAuthTime = null
    if (!state.envoySerial) state.envoySerial = null

    // Set initial attribute values
    sendEvent(name: "authStatus", value: "Initialized")
    sendEvent(name: "sessionExpiry", value: state.sessionExpiry ?: "Unknown")
    sendEvent(name: "lastAuthTime", value: state.lastAuthTime ?: "Never")
    sendEvent(name: "authAttempts", value: state.authAttempts)

    if (pollInterval && pollInterval > 0) {
        runIn(5, "refresh")
        schedule("0 */${pollInterval} * * * ?", "refresh")
        log.info "Scheduled refresh every ${pollInterval} minutes"
        if (logEnable) log.debug "Using session duration: ${sessionDuration ?: 24} hours"
    } else {
        log.warn "Poll interval not configured, data will only update manually"
    }

    // Log current session status
    if (isSessionValid()) {
        log.info "Valid session found, expires: ${state.sessionExpiry}"
    } else {
        log.info "No valid session found, will authenticate on first refresh"
    }
}

def createChildDevices() {
    def children = [
        [dni: "${device.deviceNetworkId}-production", name: "Solar Production", label: "${device.displayName} - Solar Production"],
        [dni: "${device.deviceNetworkId}-consumption", name: "Home Consumption", label: "${device.displayName} - Home Consumption"],
        [dni: "${device.deviceNetworkId}-export", name: "Export Power", label: "${device.displayName} - Export Power"]
    ]

    children.each { child ->
        def existing = getChildDevice(child.dni)
        if (!existing) {
            try {
                addChildDevice("custom", "Enphase Envoy Lux Sensor", child.dni, [
                    name: child.name,
                    label: child.label,
                    isComponent: false
                ])
                log.info "Created child device: ${child.label}"
            } catch (Exception e) {
                log.error "Failed to create child device ${child.label}: ${e.message}"
            }
        }
    }
}

def deleteChildDevices() {
    getChildDevices().each { child ->
        try {
            deleteChildDevice(child.deviceNetworkId)
            log.info "Deleted child device: ${child.displayName}"
        } catch (Exception e) {
            log.error "Failed to delete child device: ${e.message}"
        }
    }
}

def refresh() {
    if (logEnable) log.debug "Refreshing Enphase Envoy data"

    if (!envoyIP || !enphaseUsername || !enphasePassword) {
        log.error "Missing required configuration: IP address, username, and/or password"
        sendEvent(name: "authStatus", value: "Configuration Error")
        return
    }

    // Check if we need to authenticate
    if (!isSessionValid()) {
        if (logAuth) log.info "Session invalid or expired, starting authentication..."
        authenticate()
        if (!state.sessionId) {
            log.error "Authentication failed, cannot fetch data"
            return
        }
    }

    def uri = "https://${envoyIP}/production.json"
    def headers = [
        "Cookie": "sessionId=${state.sessionId}",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    ]

    if (logEnable) log.debug "Fetching production data from: ${uri}"

    try {
        httpGet([
            uri: uri,
            headers: headers,
            ignoreSSLIssues: true,
            timeout: 30
        ]) { resp ->
            if (resp.status == 200) {
                if (logEnable) log.debug "Successfully retrieved production data"
                parseEnvoyData(resp.data)
                sendEvent(name: "authStatus", value: "Authenticated")

                // Update session expiry if we got a successful response
                updateSessionExpiry()

            } else if (resp.status == 401 || resp.status == 403) {
                log.warn "Authentication expired (HTTP ${resp.status}), invalidating session and re-authenticating..."
                invalidateSession()
                sendEvent(name: "authStatus", value: "Re-authenticating")

                authenticate()
                if (state.sessionId) {
                    if (logAuth) log.info "Re-authentication successful, retrying data fetch..."
                    refresh() // Retry with new session
                } else {
                    log.error "Re-authentication failed"
                }
            } else {
                log.error "HTTP error: ${resp.status}"
                sendEvent(name: "authStatus", value: "HTTP Error ${resp.status}")
            }
        }
    } catch (Exception e) {
        log.error "Error fetching data from Envoy: ${e.message}"

        if (e.message?.contains("401") || e.message?.contains("403") || e.message?.contains("Unauthorized")) {
            log.warn "Authentication error detected in exception, invalidating session"
            invalidateSession()
            sendEvent(name: "authStatus", value: "Auth Error - Will Retry")
        } else {
            sendEvent(name: "authStatus", value: "Connection Error")
        }
    }
}

def authenticate() {
    if (logAuth) log.info "Starting complete Enphase OAuth authentication process..."
    sendEvent(name: "authStatus", value: "Authenticating")

    // Track authentication attempts with time-based reset
    def now = new Date()
    def lastAttemptTime = state.lastAttemptTime ? Date.parse("yyyy-MM-dd HH:mm:ss", state.lastAttemptTime) : null

    // Reset attempts if it's been more than 1 hour since last attempt
    if (!lastAttemptTime || (now.time - lastAttemptTime.time) > (60 * 60 * 1000)) {
        state.authAttempts = 0
        if (logAuth) log.info "Resetting authentication attempts counter (time-based reset)"
    }

    state.authAttempts = (state.authAttempts ?: 0) + 1
    state.lastAttemptTime = now.format("yyyy-MM-dd HH:mm:ss")
    sendEvent(name: "authAttempts", value: state.authAttempts)

    if (state.authAttempts > 5) {
        log.error "Too many authentication attempts (${state.authAttempts}), stopping to prevent account lockout. Will reset in 1 hour."
        sendEvent(name: "authStatus", value: "Too Many Attempts - Wait 1 Hour")
        return
    }

    try {
        // Step 1: Generate PKCE parameters
        def codeVerifier = generateCodeVerifier()
        def codeChallenge = generateCodeChallenge(codeVerifier)

        if (logAuth) log.info "Step 1: Generated PKCE parameters (verifier length: ${codeVerifier.length()})"

        // Step 2: Get login page and extract form data
        def authUrl = buildAuthorizationUrl(codeChallenge)
        if (!authUrl) {
            log.error "Failed to build authorization URL - cannot proceed with authentication"
            sendEvent(name: "authStatus", value: "Serial Number Error")
            return
        }

        def loginFormData = getLoginFormData(authUrl, codeChallenge)

        if (!loginFormData) {
            log.error "Failed to get login form data"
            sendEvent(name: "authStatus", value: "Login Form Error")
            return
        }

        if (logAuth) log.info "Step 2: Retrieved login form data with CSRF token"

        // Step 3: Submit login credentials
        def authCode = submitLoginCredentials(loginFormData)
        if (!authCode) {
            log.error "Failed to get authorization code from login"
            sendEvent(name: "authStatus", value: "Login Failed")
            return
        }

        if (logAuth) log.info "Step 3: Obtained authorization code: ${authCode}"

        // Step 4: Exchange authorization code for JWT
        def accessToken = exchangeCodeForJWT(authCode, codeVerifier)
        if (!accessToken) {
            log.error "Failed to exchange authorization code for JWT"
            sendEvent(name: "authStatus", value: "JWT Exchange Failed")
            return
        }

        if (logAuth) log.info "Step 4: Obtained JWT access token (${accessToken.length()} chars)"

        // Step 5: Exchange JWT for session cookie
        def sessionId = exchangeJWTForSession(accessToken)
        if (sessionId) {
            state.sessionId = sessionId
            state.lastAuthTime = new Date().format("yyyy-MM-dd HH:mm:ss")
            updateSessionExpiry()

            // Reset auth attempts on success
            state.authAttempts = 0

            log.info "Authentication successful! Session ID: ${sessionId}"
            sendEvent(name: "authStatus", value: "Authenticated")
            sendEvent(name: "lastAuthTime", value: state.lastAuthTime)
            sendEvent(name: "authAttempts", value: 0)

        } else {
            log.error "Failed to exchange JWT for session cookie"
            sendEvent(name: "authStatus", value: "Session Exchange Failed")
        }

    } catch (Exception e) {
        log.error "Authentication failed with exception: ${e.message}"
        if (logEnable) log.debug "Authentication stack trace", e
        sendEvent(name: "authStatus", value: "Authentication Failed")
    }
}

// Session management methods
private boolean isSessionValid() {
    // Check if manual session ID is provided
    if (manualSessionId?.trim()) {
        state.sessionId = manualSessionId.trim()
        if (logAuth) log.info "Using manual session ID: ${state.sessionId}"
        updateSessionExpiry() // Set expiry for manual session
        return true
    }

    if (!state.sessionId) {
        if (logAuth) log.debug "No session ID found"
        return false
    }

    if (!state.sessionExpiry) {
        if (logAuth) log.debug "No session expiry found, assuming session expired"
        return false
    }

    def now = new Date()
    def expiry = Date.parse("yyyy-MM-dd HH:mm:ss", state.sessionExpiry)

    if (now.after(expiry)) {
        if (logAuth) log.info "Session expired at ${state.sessionExpiry}, current time: ${now.format('yyyy-MM-dd HH:mm:ss')}"
        return false
    }

    if (logEnable) log.debug "Session valid until ${state.sessionExpiry}"
    return true
}

private void updateSessionExpiry() {
    def sessionDurationHours = sessionDuration ?: 24
    def expiry = new Date(now() + (sessionDurationHours * 60 * 60 * 1000))
    state.sessionExpiry = expiry.format("yyyy-MM-dd HH:mm:ss")
    sendEvent(name: "sessionExpiry", value: state.sessionExpiry)
    if (logAuth) log.info "Updated session expiry to: ${state.sessionExpiry}"
}

private void invalidateSession() {
    if (logAuth) log.info "Invalidating current session"
    state.sessionId = null
    state.sessionExpiry = null
    sendEvent(name: "sessionExpiry", value: "Expired")
}

// Serial number retrieval method
private String getEnvoySerialNumber() {
    // Check if user provided a manual serial number first
    if (envoySerial?.trim()) {
        if (logAuth) log.info "Using manual Envoy serial number: ${envoySerial.trim()}"
        return envoySerial.trim()
    }

    try {
        if (logAuth) log.info "Fetching Envoy serial number from device..."

        def uri = "https://${envoyIP}/"
        def headers = [
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        ]

        def serialNumber = null

        httpGet([
            uri: uri,
            headers: headers,
            ignoreSSLIssues: true,
            timeout: 30
        ]) { resp ->
            if (resp.status == 200) {
                def htmlContent = null

                // Handle different response data types
                if (resp.data instanceof String) {
                    htmlContent = resp.data
                } else if (resp.data?.hasProperty('bytes')) {
                    def bytes = resp.data.bytes
                    htmlContent = new String(bytes, "UTF-8")
                } else if (resp.data) {
                    htmlContent = resp.data.toString()
                } else {
                    htmlContent = resp.text ?: ""
                }

                if (htmlContent) {
                    // Try to extract from title first (e.g., "Envoy 123456789012")
                    def titleMatch = htmlContent =~ /<title>Envoy\s+(\d+)<\/title>/
                    if (titleMatch) {
                        serialNumber = titleMatch[0][1]
                        if (logAuth) log.debug "Found serial number in title: ${serialNumber}"
                    } else {
                        // Try to extract from window.BackboneConfig.serial
                        def configMatch = htmlContent =~ /serial:\s*['\""](\d+)['\"]/
                        if (configMatch) {
                            serialNumber = configMatch[0][1]
                            if (logAuth) log.debug "Found serial number in config: ${serialNumber}"
                        } else {
                            // Try alternative patterns
                            def altMatch = htmlContent =~ /(\d{12})/
                            if (altMatch) {
                                serialNumber = altMatch[0][1]
                                if (logAuth) log.debug "Found potential serial number: ${serialNumber}"
                            }
                        }
                    }
                }
            } else {
                log.warn "Failed to fetch Envoy home page, HTTP status: ${resp.status}"
            }
        }

        if (!serialNumber) {
            log.error "Could not extract serial number from Envoy device - authentication will fail"
            return null
        }

        if (logAuth) log.info "Successfully retrieved Envoy serial number: ${serialNumber}"
        return serialNumber

    } catch (Exception e) {
        log.error "Error fetching Envoy serial number: ${e.message}"
        if (logAuth) log.debug "Serial number fetch error details", e
        return null
    }
}

// PKCE and OAuth utility methods
private String generateCodeVerifier() {
    // Generate 64 character random string (43-128 chars allowed)
    // Using Hubitat's built-in randomization
    def chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    def verifier = new StringBuilder()

    for (int i = 0; i < 64; i++) {
        def randomIndex = Math.abs(new Random().nextInt()) % chars.length()
        verifier.append(chars.charAt(randomIndex))
    }

    return verifier.toString()
}

private String generateCodeChallenge(String codeVerifier) {
    // SHA256 hash and Base64URL encode using Hubitat-compatible methods
    def digest = MessageDigest.getInstance("SHA-256")
    def hash = digest.digest(codeVerifier.getBytes("UTF-8"))

    // Convert to base64 using Hubitat's built-in method
    def base64 = hash.encodeBase64().toString()

    // Base64URL encoding (replace + with -, / with _, remove padding =)
    return base64.replace('+', '-')
                 .replace('/', '_')
                 .replace('=', '')
}

private String urlEncode(String value) {
    // Use Hubitat-compatible URL encoding
    return java.net.URLEncoder.encode(value, "UTF-8")
}

private String buildAuthorizationUrl(String codeChallenge) {
    def clientId = "envoy-ui-client"
    def redirectUri = "https://${envoyIP}/auth/callback"
    def scope = getEnvoySerialNumber() // Dynamically fetch the device serial number

    if (!scope) {
        log.error "Failed to retrieve Envoy serial number - cannot build authorization URL"
        return null
    }

    if (logAuth) log.debug "Building authorization URL with serial: ${scope}"

    def authUrl = "https://entrez.enphaseenergy.com/authorize" +
        "?code_challenge=${urlEncode(codeChallenge)}" +
        "&client_id=${urlEncode(clientId)}" +
        "&redirect_uri=${urlEncode(redirectUri)}" +
        "&scope=${urlEncode(scope)}" +
        "&response_type=code" +
        "&code_challenge_method=S256"

    return authUrl
}

private Map getLoginFormData(String authUrl, String codeChallenge) {
    try {
        if (logAuth) log.info "Fetching login page from: ${authUrl}"

        def loginResponse = null
        def httpError = false

        // Try a different approach to get raw HTML
        def params = [
            uri: authUrl,
            headers: [
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            ],
            contentType: "TEXT",
            ignoreSSLIssues: true,
            timeout: 30
        ]

        try {
            def httpResponse = httpGet(params) { resp ->
                if (resp.status == 200) {
                    if (logAuth) {
                        log.debug "Response status: ${resp.status}"
                        log.debug "Response content type: ${resp.headers['Content-Type']}"
                        log.debug "Response data available: ${resp.data ? 'yes' : 'no'}"
                    }

                    // Handle different response data types
                    if (resp.data instanceof String) {
                        loginResponse = resp.data
                        if (logAuth) log.debug "Got String response directly"
                    } else if (resp.data) {
                        if (logAuth) log.debug "Response data is not a String, trying to read as InputStream"

                        // Try to read as InputStream
                        try {
                            if (resp.data.hasProperty('bytes')) {
                                def bytes = resp.data.bytes
                                loginResponse = new String(bytes, "UTF-8")
                                if (logAuth) log.debug "Successfully read InputStream as UTF-8 string"
                            } else {
                                loginResponse = resp.data.toString()
                                if (logAuth) log.debug "Used toString() fallback"
                            }
                        } catch (Exception e) {
                            if (logAuth) log.debug "Failed to read InputStream: ${e.message}"
                            loginResponse = resp.data.toString()
                        }
                    } else {
                        // Try to read as raw text
                        loginResponse = resp.text ?: ""
                        if (logAuth) log.debug "Used resp.text fallback"
                    }

                    if (logAuth) {
                        log.debug "Successfully fetched login page (${loginResponse?.length()} characters)"
                        if (loginResponse?.startsWith("<!DOCTYPE") || loginResponse?.startsWith("<html")) {
                            log.debug "Got raw HTML response (starts with DOCTYPE or html tag)"
                        } else {
                            log.debug "Got processed response (no DOCTYPE found)"
                            log.debug "Response starts with: ${loginResponse?.take(100)}"
                        }
                    }
                } else {
                    log.error "Failed to fetch login page, HTTP status: ${resp.status}"
                    httpError = true
                }
                return resp
            }
        } catch (Exception httpEx) {
            log.error "HTTP request failed: ${httpEx.message}"
            httpError = true
        }

        // Check if we got a response after the callback completed
        if (httpError || !loginResponse) {
            log.error "No login response received or HTTP error occurred"
            return null
        }

        // Debug: Log first 1000 characters of login response
        if (logAuth) {
            log.debug "Login page content (first 1000 chars): ${loginResponse.take(1000)}"
        }

        // Extract form fields using regex patterns
        def csrfToken = extractFormValue(loginResponse, "_csrf")
        def formCodeChallenge = extractFormValue(loginResponse, "codeChallenge")
        def formRedirectUri = extractFormValue(loginResponse, "redirectUri")
        def formClient = extractFormValue(loginResponse, "client")
        def formClientId = extractFormValue(loginResponse, "clientId")
        def formAuthFlow = extractFormValue(loginResponse, "authFlow")
        def formSerialNum = extractFormValue(loginResponse, "serialNum")
        def formGrantType = extractFormValue(loginResponse, "grantType")
        def formState = extractFormValue(loginResponse, "state")
        def formInvalidSerial = extractFormValue(loginResponse, "invalidSerialNum")

        if (!csrfToken) {
            log.error "Failed to extract CSRF token from login page"
            if (logAuth) {
                // Look for any input tags with 'csrf' or 'token' in the name
                def csrfMatches = loginResponse.findAll(/(?i)<input[^>]*name[^>]*(?:csrf|token)[^>]*>/)
                log.debug "Found potential CSRF fields: ${csrfMatches}"
            }
            return null
        }

        if (logAuth) log.debug "Extracted CSRF token and ${formCodeChallenge ? 'found' : 'missing'} code challenge"

        return [
            csrfToken: csrfToken,
            codeChallenge: formCodeChallenge ?: codeChallenge,
            redirectUri: formRedirectUri,
            client: formClient,
            clientId: formClientId,
            authFlow: formAuthFlow,
            serialNum: formSerialNum,
            grantType: formGrantType,
            state: formState,
            invalidSerialNum: formInvalidSerial
        ]

    } catch (Exception e) {
        log.error "Error getting login form data: ${e.message}"
        if (logEnable) log.debug "Login form data error stack trace", e
        return null
    }
}

private String extractFormValue(String html, String fieldName) {
    // Try multiple patterns to extract form values
    def patterns = [
        ~/name=["']${fieldName}["'][^>]*value=["']([^"']*)["']/,
        ~/name="${fieldName}"[^>]*value="([^"]*)"/,
        ~/name='${fieldName}'[^>]*value='([^']*)'/,
        ~/value=["']([^"']*)["'][^>]*name=["']${fieldName}["']/
    ]

    for (def pattern : patterns) {
        def matcher = html =~ pattern
        if (matcher) {
            def value = matcher[0][1]
            if (logAuth) log.debug "Extracted ${fieldName}: ${value}"
            return value
        }
    }

    if (logAuth) log.warn "Could not extract form field: ${fieldName}"
    return null
}

private String submitLoginCredentials(Map formData) {
    try {
        if (logAuth) log.info "Submitting login credentials to Enphase..."

        // Build POST data with all form fields
        def postData = [
            username: enphaseUsername,
            password: enphasePassword,
            _csrf: formData.csrfToken,
            codeChallenge: formData.codeChallenge,
            redirectUri: formData.redirectUri,
            client: formData.client,
            clientId: formData.clientId,
            authFlow: formData.authFlow,
            serialNum: formData.serialNum,
            grantType: formData.grantType,
            state: formData.state,
            invalidSerialNum: formData.invalidSerialNum
        ]

        def authCode = null
        def loginError = false

        httpPost([
            uri: "https://entrez.enphaseenergy.com/login",
            headers: [
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": buildAuthorizationUrl(formData.codeChallenge)
            ],
            body: postData,
            ignoreSSLIssues: true,
            timeout: 30
        ]) { resp ->
            if (resp.status == 302 || resp.status == 301) {
                def location = resp.headers.Location
                if (logAuth) log.debug "Login redirect to: ${location}"

                if (location?.contains("${envoyIP}/auth/callback")) {
                    def codeMatch = location =~ /code=([^&]*)/
                    if (codeMatch) {
                        authCode = codeMatch[0][1]
                        if (logAuth) log.debug "Successfully extracted auth code from redirect"
                    }
                } else {
                    log.warn "Redirect location does not contain expected callback URL: ${location}"
                }
            } else {
                log.error "Unexpected login response status: ${resp.status}"
                loginError = true
            }
        }

        // Check if we got a successful result after the callback completed
        if (loginError) {
            log.error "Login submission failed"
            return null
        }

        if (!authCode) {
            log.error "No authorization code extracted from login response"
        }

        return authCode

    } catch (Exception e) {
        log.error "Error submitting login credentials: ${e.message}"
        return null
    }
}

private String exchangeCodeForJWT(String authCode, String codeVerifier) {
    try {
        if (logAuth) log.info "Exchanging authorization code for JWT..."

        def jwtPayload = [
            client_id: "envoy-ui-1",
            grant_type: "authorization_code",
            redirect_uri: "https://${envoyIP}/auth/callback",
            code_verifier: codeVerifier,
            code: authCode
        ]

        def jsonBuilder = new JsonBuilder(jwtPayload)
        def accessToken = null

        httpPost([
            uri: "https://${envoyIP}/auth/get_jwt",
            headers: [
                "Content-Type": "application/json",
                "Accept": "application/json"
            ],
            body: jsonBuilder.toString(),
            ignoreSSLIssues: true,
            timeout: 30
        ]) { resp ->
            if (logAuth) {
                log.debug "JWT exchange response status: ${resp.status}"
                log.debug "JWT exchange response headers: ${resp.headers}"
            }

            if (resp.status == 200) {
                def rawResponse = null

                // Handle different response types like we did for login page
                if (resp.data instanceof String) {
                    rawResponse = resp.data
                } else if (resp.data?.hasProperty('bytes')) {
                    def bytes = resp.data.bytes
                    rawResponse = new String(bytes, "UTF-8")
                } else if (resp.data) {
                    rawResponse = resp.data.toString()
                }

                if (logAuth) {
                    log.debug "JWT raw response (${rawResponse?.length()} chars): ${rawResponse}"
                }

                try {
                    // First try JSON parsing
                    def jsonSlurper = new JsonSlurper()
                    def tokenData = jsonSlurper.parseText(rawResponse)
                    accessToken = tokenData.access_token

                    if (logAuth) log.debug "Successfully obtained JWT via JSON (${accessToken?.length()} characters)"
                } catch (Exception jsonEx) {
                    if (logAuth) log.debug "JSON parsing failed, trying alternative parsing: ${jsonEx.message}"

                    // Try parsing as form-encoded or direct token response
                    if (rawResponse?.contains("access_token=")) {
                        // Extract token from form-like response
                        def tokenMatch = rawResponse =~ /access_token=([^&\s}]+)/
                        if (tokenMatch) {
                            accessToken = tokenMatch[0][1]
                            if (logAuth) log.debug "Successfully extracted JWT via regex (${accessToken?.length()} characters)"
                        }
                    } else if (rawResponse?.startsWith("ey")) {
                        // Might be a raw JWT token (JWTs start with "ey")
                        accessToken = rawResponse.trim()
                        if (logAuth) log.debug "Using raw response as JWT token (${accessToken?.length()} characters)"
                    }

                    if (!accessToken) {
                        log.error "Failed to parse JWT response in any format"
                        log.error "Raw response: ${rawResponse}"
                    }
                }
            } else {
                log.error "Failed to get JWT, HTTP status: ${resp.status}"
                if (logAuth) {
                    def errorResponse = resp.data?.toString() ?: "No response body"
                    log.debug "JWT error response: ${errorResponse}"
                }
            }
        }

        return accessToken

    } catch (Exception e) {
        log.error "Error exchanging code for JWT: ${e.message}"
        return null
    }
}

private String exchangeJWTForSession(String accessToken) {
    try {
        if (logAuth) log.info "Exchanging JWT for session cookie..."

        def sessionId = null
        httpPost([
            uri: "https://${envoyIP}/auth/check_jwt",
            headers: [
                "Authorization": "Bearer ${accessToken}",
                "Content-Type": "application/json"
            ],
            ignoreSSLIssues: true,
            timeout: 30
        ]) { resp ->
            if (resp.status == 200) {
                // Extract sessionId from Set-Cookie header
                def setCookieHeader = resp.headers['Set-Cookie']
                if (setCookieHeader) {
                    def cookieString = setCookieHeader.toString()
                    def sessionMatch = cookieString =~ /sessionId=([^;]*)/
                    if (sessionMatch) {
                        sessionId = sessionMatch[0][1]
                        if (logAuth) log.debug "Extracted session ID from cookie: ${sessionId}"
                    }
                }

                if (!sessionId) {
                    log.warn "No session cookie found in response headers"
                }
            } else if (resp.status == 503) {
                log.error "Too many sessions error (503) - device may have session limit"
            } else {
                log.error "Failed to get session cookie, HTTP status: ${resp.status}"
            }
        }

        return sessionId

    } catch (Exception e) {
        log.error "Error exchanging JWT for session: ${e.message}"
        return null
    }
}

def parseEnvoyData(data) {
    if (logEnable) log.debug "Parsing Envoy production data..."

    try {
        def solarProduction = 0
        def homeConsumption = 0
        def netConsumption = 0

        // Parse production data - look for EIM production measurement
        data.production?.each { prod ->
            if (prod.measurementType == "production") {
                solarProduction = prod.wNow ?: 0
                if (logEnable) log.debug "Found production measurement: ${solarProduction}W"
            }
        }

        // Parse consumption data
        data.consumption?.each { cons ->
            if (cons.measurementType == "total-consumption") {
                homeConsumption = cons.wNow ?: 0
                if (logEnable) log.debug "Found total consumption: ${homeConsumption}W"
            } else if (cons.measurementType == "net-consumption") {
                netConsumption = cons.wNow ?: 0
                if (logEnable) log.debug "Found net consumption: ${netConsumption}W"
            }
        }

        // Calculate export power (negative net = export, positive net = import, we only want export)
        def exportPower = netConsumption < 0 ? Math.abs(netConsumption) : 0

        // Scale values for lux display (compatible with existing lux sensor implementation)
        def scale = scaleFactor ?: 1000
        def solarLux = Math.round((solarProduction / scale) * 10) / 10
        def consumptionLux = Math.round((homeConsumption / scale) * 10) / 10
        def exportLux = Math.round((exportPower / scale) * 10) / 10

        if (logEnable) {
            log.debug "Calculated values - Solar: ${solarProduction}W (${solarLux}lux), Home: ${homeConsumption}W (${consumptionLux}lux), Export: ${exportPower}W (${exportLux}lux)"
            log.debug "Scale factor: ${scale}, Raw net consumption: ${netConsumption}W"
        }

        // Update parent device attributes (maintain compatibility with v3)
        sendEvent(name: "power", value: solarProduction, unit: "W")
        sendEvent(name: "energy", value: (solarProduction / 1000), unit: "kWh")
        sendEvent(name: "solarProduction", value: solarProduction, unit: "W")
        sendEvent(name: "homeConsumption", value: homeConsumption, unit: "W")
        sendEvent(name: "netConsumption", value: netConsumption, unit: "W")
        sendEvent(name: "exportPower", value: exportPower, unit: "W")
        sendEvent(name: "lastUpdated", value: new Date().format("yyyy-MM-dd HH:mm:ss"))

        // Update child devices (fully compatible with existing lux sensor)
        updateChildDevice("${device.deviceNetworkId}-production", solarLux, solarProduction, "Solar Production")
        updateChildDevice("${device.deviceNetworkId}-consumption", consumptionLux, homeConsumption, "Home Consumption")
        updateChildDevice("${device.deviceNetworkId}-export", exportLux, exportPower, "Export Power")

        // Summary logging
        log.info "Envoy data updated successfully - Solar: ${solarProduction}W (${solarLux}lux), Home: ${homeConsumption}W (${consumptionLux}lux), Export: ${exportPower}W (${exportLux}lux)"

    } catch (Exception e) {
        log.error "Error parsing Envoy data: ${e.message}"
        if (logEnable) log.debug "Data parsing error details", e
    }
}

// Helper method to update child devices with comprehensive logging
private void updateChildDevice(String dni, Double luxValue, Double powerValue, String deviceType) {
    def childDevice = getChildDevice(dni)
    if (childDevice) {
        childDevice.sendEvent(name: "illuminance", value: luxValue, unit: "lux")
        childDevice.sendEvent(name: "powerValue", value: powerValue, unit: "W")

        if (logEnable) log.debug "${deviceType} child device updated: ${luxValue}lux, ${powerValue}W"
    } else {
        if (logEnable) log.debug "${deviceType} child device not found: ${dni}"
    }
}

def configure() {
    refresh()
}

// Manual command to clear session and force re-authentication
def clearSession() {
    log.info "Manual session clear requested"
    invalidateSession()

    // Reset authentication attempts and timing
    state.authAttempts = 0
    state.lastAttemptTime = null

    sendEvent(name: "authStatus", value: "Session Cleared")
    sendEvent(name: "authAttempts", value: 0)
    log.info "Session cleared and auth attempts reset, next refresh will re-authenticate"
}