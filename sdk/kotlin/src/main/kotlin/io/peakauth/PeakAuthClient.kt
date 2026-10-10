package io.peakauth

import io.peakauth.crypto.JwksProvider
import io.peakauth.crypto.JwtVerifier
import io.peakauth.crypto.SafeJsonParser
import io.peakauth.models.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder

/**
 * Cliente principal del SDK de Peak Auth para Kotlin y Android.
 *
 * Administra el ciclo de vida de autenticación OAuth 2.0 con PKCE, validación offline
 * de JWTs asimétricos (RS256) y renovación automática de tokens.
 */
class PeakAuthClient(
    val config: PeakAuthConfig,
    val tokenStorage: TokenStorage = InMemoryTokenStorage(),
    private val jwksProvider: JwksProvider = JwksProvider(
        jwksUrl = "${config.normalizedIssuerUrl}/.well-known/jwks.json",
        cacheTtlMs = config.jwksCacheTtlMs,
        connectTimeoutMs = config.connectTimeoutMs,
        readTimeoutMs = config.readTimeoutMs
    )
) {
    private val jwtVerifier = JwtVerifier(config, jwksProvider)

    @Volatile
    private var openIdConfigCache: Pair<OpenIdConfiguration, Long>? = null

    /**
     * Genera un par PKCE criptográfico (code_verifier y code_challenge).
     */
    fun generatePkce(length: Int = 64): PkcePair {
        return PkceHelper.generate(length)
    }

    /**
     * Genera un valor 'state' aleatorio seguro para mitigar CSRF.
     */
    fun generateState(length: Int = 32): String {
        return PkceHelper.generateState(length)
    }

    /**
     * Valida dos estados de forma segura y en tiempo constante.
     */
    fun validateState(expectedState: String?, actualState: String?): Boolean {
        return PkceHelper.validateState(expectedState, actualState)
    }

    /**
     * Construye la URL de inicio de sesión de Peak Auth con soporte para PKCE.
     * Para clientes públicos (sin clientSecret), codeChallenge es obligatorio.
     */
    fun getAuthorizationUrl(
        state: String? = null,
        codeChallenge: String? = null,
        redirectUri: String? = null,
        scope: String? = null,
        extraParams: Map<String, String> = emptyMap()
    ): String {
        val targetRedirect = redirectUri ?: config.redirectUri
        require(!targetRedirect.isNullOrBlank()) {
            "PeakAuth: redirectUri es requerido para construir la URL de autorización"
        }

        if (config.clientSecret.isNullOrBlank() && codeChallenge.isNullOrBlank()) {
            throw IllegalArgumentException("PeakAuth: code_challenge es obligatorio para clientes públicos (sin clientSecret)")
        }

        val sb = StringBuilder("${config.normalizedIssuerUrl}/oauth/authorize?")
        sb.append("client_id=").append(urlEncode(config.clientId))
        sb.append("&redirect_uri=").append(urlEncode(targetRedirect))
        sb.append("&response_type=code")

        if (!state.isNullOrBlank()) {
            sb.append("&state=").append(urlEncode(state))
        }
        if (!codeChallenge.isNullOrBlank()) {
            sb.append("&code_challenge=").append(urlEncode(codeChallenge))
            sb.append("&code_challenge_method=S256")
        }
        if (!scope.isNullOrBlank()) {
            sb.append("&scope=").append(urlEncode(scope))
        }

        for ((key, value) in extraParams) {
            sb.append("&").append(urlEncode(key)).append("=").append(urlEncode(value))
        }

        return sb.toString()
    }

    /**
     * Construye la URL de cierre de sesión centralizado (Federated Logout).
     */
    fun getLogoutUrl(
        postLogoutRedirectUri: String? = null,
        state: String? = null,
        idTokenHint: String? = null
    ): String {
        val sb = StringBuilder("${config.normalizedIssuerUrl}/oauth/logout?")
        sb.append("client_id=").append(urlEncode(config.clientId))

        val redirect = postLogoutRedirectUri ?: config.redirectUri
        if (!redirect.isNullOrBlank()) {
            sb.append("&post_logout_redirect_uri=").append(urlEncode(redirect))
        }
        if (!state.isNullOrBlank()) {
            sb.append("&state=").append(urlEncode(state))
        }
        if (!idTokenHint.isNullOrBlank()) {
            sb.append("&id_token_hint=").append(urlEncode(idTokenHint))
        }

        return sb.toString()
    }

    /**
     * Intercambia un código de autorización por un Access Token (+ Refresh Token) en `/oauth/token`.
     * Para clientes públicos (sin clientSecret), codeVerifier es obligatorio.
     */
    fun exchangeCode(
        code: String,
        codeVerifier: String? = null,
        redirectUri: String? = null
    ): TokenResponse {
        val targetRedirect = redirectUri ?: config.redirectUri
        require(!targetRedirect.isNullOrBlank()) {
            "PeakAuth: redirectUri es requerido para el canje de código"
        }

        if (config.clientSecret.isNullOrBlank() && codeVerifier.isNullOrBlank()) {
            throw IllegalArgumentException("PeakAuth: code_verifier es obligatorio para clientes públicos (sin clientSecret)")
        }

        val bodyParams = mutableMapOf(
            "grant_type" to "authorization_code",
            "client_id" to config.clientId,
            "code" to code,
            "redirect_uri" to targetRedirect
        )

        if (!config.clientSecret.isNullOrBlank()) {
            bodyParams["client_secret"] = config.clientSecret
        }
        if (!codeVerifier.isNullOrBlank()) {
            bodyParams["code_verifier"] = codeVerifier
        }

        val formData = bodyParams.entries.joinToString("&") { (k, v) ->
            "${urlEncode(k)}=${urlEncode(v)}"
        }

        val responseJson = executeHttpRequest(
            urlString = "${config.normalizedIssuerUrl}/oauth/token",
            method = "POST",
            contentType = "application/x-www-form-urlencoded",
            body = formData
        )

        val tokenResponse = parseTokenResponse(responseJson)
        tokenStorage.saveTokens(tokenResponse.accessToken, tokenResponse.refreshToken)
        return tokenResponse
    }

    /**
     * Renueva el Access Token utilizando un Refresh Token de manera sincronizada (single-flight)
     * para evitar que peticiones concurrentes invaliden refresh tokens rotativos.
     */
    @Synchronized
    fun refreshToken(
        refreshToken: String? = null,
        clientId: String? = null
    ): TokenResponse {
        val tokenToUse = refreshToken ?: tokenStorage.getRefreshToken()
            ?: throw IllegalStateException("PeakAuth: No hay un refresh token disponible para renovar la sesión")

        val targetClientId = clientId ?: config.clientId
        val jsonPayload = buildJson(
            "refresh_token" to tokenToUse,
            "client_id" to targetClientId
        )

        val responseJson = executeHttpRequest(
            urlString = "${config.normalizedIssuerUrl}/api/v1/refresh",
            method = "POST",
            contentType = "application/json",
            body = jsonPayload
        )

        val tokenResponse = parseTokenResponse(responseJson)
        tokenStorage.saveTokens(tokenResponse.accessToken, tokenResponse.refreshToken ?: tokenToUse)
        return tokenResponse
    }

    /**
     * Valida offline un token JWT verificando su firma asimétrica RS256, emisor, audiencia y expiración.
     */
    fun verifyToken(tokenString: String? = null): PeakClaims {
        val tokenToVerify = tokenString ?: tokenStorage.getAccessToken()
            ?: throw IllegalStateException("PeakAuth: No hay un access token disponible para verificar")

        return jwtVerifier.verify(tokenToVerify)
    }

    /**
     * Realiza una introspección online del token contra el servidor (`/api/v1/introspect`).
     */
    fun introspectToken(tokenString: String? = null): IntrospectionResponse {
        require(!config.clientSecret.isNullOrBlank()) {
            "PeakAuth: clientSecret es requerido para realizar introspección online de tokens"
        }

        val tokenToIntrospect = tokenString ?: tokenStorage.getAccessToken()
            ?: throw IllegalStateException("PeakAuth: No hay un access token disponible para introspección")

        val jsonPayload = buildJson("token" to tokenToIntrospect)
        val headers = mapOf(
            "X-App-Id" to config.clientId,
            "X-App-Secret" to config.clientSecret
        )

        val responseJson = executeHttpRequest(
            urlString = "${config.normalizedIssuerUrl}/api/v1/introspect",
            method = "POST",
            contentType = "application/json",
            body = jsonPayload,
            headers = headers
        )

        return parseIntrospectionResponse(responseJson)
    }

    /**
     * Descarga y cachea la configuración OIDC de descubrimiento desde `/.well-known/openid-configuration`.
     */
    fun getOpenIdConfiguration(): OpenIdConfiguration {
        val cached = openIdConfigCache
        val now = System.currentTimeMillis()
        if (cached != null && cached.second > now) {
            return cached.first
        }

        val responseJson = executeHttpRequest(
            urlString = "${config.normalizedIssuerUrl}/.well-known/openid-configuration",
            method = "GET"
        )

        val oidcConfig = parseOpenIdConfiguration(responseJson)
        openIdConfigCache = Pair(oidcConfig, now + (60 * 60 * 1000L))
        return oidcConfig
    }

    /**
     * Cierra la sesión local borrando los tokens almacenados en [tokenStorage].
     */
    fun logout() {
        tokenStorage.clear()
    }

    // ---------------------------------------------------------------------------------------------
    // HTTP & JSON Helpers
    // ---------------------------------------------------------------------------------------------

    private fun executeHttpRequest(
        urlString: String,
        method: String,
        contentType: String? = null,
        body: String? = null,
        headers: Map<String, String> = emptyMap()
    ): String {
        val conn = (URI(urlString).toURL().openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = config.connectTimeoutMs
            readTimeout = config.readTimeoutMs
            setRequestProperty("Accept", "application/json")
            if (contentType != null) {
                setRequestProperty("Content-Type", contentType)
            }
            for ((k, v) in headers) {
                setRequestProperty(k, v)
            }
        }

        try {
            if (body != null && (method == "POST" || method == "PUT")) {
                conn.doOutput = true
                OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use {
                    it.write(body)
                    it.flush()
                }
            }

            val statusCode = conn.responseCode
            val stream = if (statusCode in 200..299) conn.inputStream else conn.errorStream
            val responseText = stream?.let {
                BufferedReader(InputStreamReader(it, Charsets.UTF_8)).use { reader -> reader.readText() }
            } ?: ""

            if (statusCode !in 200..299) {
                var errorDesc = "HTTP $statusCode: $responseText"
                try {
                    val errMap = SafeJsonParser.parseObject(responseText)
                    errorDesc = SafeJsonParser.getString(errMap, "error_description")
                        ?: SafeJsonParser.getString(errMap, "error")
                        ?: errorDesc
                } catch (_: Exception) {}
                throw RuntimeException("PeakAuth request falló ($statusCode): $errorDesc")
            }

            return responseText
        } finally {
            conn.disconnect()
        }
    }

    private fun parseTokenResponse(json: String): TokenResponse {
        val root = SafeJsonParser.parseObject(json)
        val accessToken = SafeJsonParser.getString(root, "access_token")
            ?: throw IllegalStateException("PeakAuth: access_token ausente en respuesta: $json")
        val tokenType = SafeJsonParser.getString(root, "token_type") ?: "Bearer"
        val expiresIn = SafeJsonParser.getLong(root, "expires_in") ?: 3600L
        val refreshToken = SafeJsonParser.getString(root, "refresh_token")
        val scope = SafeJsonParser.getString(root, "scope")

        return TokenResponse(
            accessToken = accessToken,
            tokenType = tokenType,
            expiresIn = expiresIn,
            refreshToken = refreshToken,
            scope = scope
        )
    }

    private fun parseIntrospectionResponse(json: String): IntrospectionResponse {
        val root = SafeJsonParser.parseObject(json)
        val active = SafeJsonParser.getBoolean(root, "active") ?: false
        val sub = SafeJsonParser.getString(root, "sub")
        val clientId = SafeJsonParser.getString(root, "client_id")
        val exp = SafeJsonParser.getLong(root, "exp")
        val iat = SafeJsonParser.getLong(root, "iat")
        val iss = SafeJsonParser.getString(root, "iss")
        val email = SafeJsonParser.getString(root, "email")
        val mfaVerified = SafeJsonParser.getBoolean(root, "mfa_verified") ?: false
        val authzVersion = SafeJsonParser.getLong(root, "authz_version")
        val roles = SafeJsonParser.getStringList(root, "roles")

        return IntrospectionResponse(
            active = active,
            sub = sub,
            clientId = clientId,
            exp = exp,
            iat = iat,
            iss = iss,
            roles = roles,
            email = email,
            mfaVerified = mfaVerified,
            authzVersion = authzVersion
        )
    }

    private fun validateEndpointUrl(rawUrl: String, isIssuer: Boolean): URI {
        require(rawUrl.isNotBlank()) { "PeakAuth: URL no puede estar vacía" }
        val uri = try {
            URI(rawUrl)
        } catch (e: Exception) {
            throw IllegalArgumentException("PeakAuth: URL inválida o malformada: $rawUrl", e)
        }
        require(uri.isAbsolute && !uri.host.isNullOrBlank()) {
            "PeakAuth: URL debe ser absoluta y tener un host válido: $rawUrl"
        }
        require(uri.userInfo == null) {
            "PeakAuth: URL no puede contener credenciales de usuario: $rawUrl"
        }
        require(uri.fragment == null) {
            "PeakAuth: URL no puede contener fragmentos (#): $rawUrl"
        }
        if (isIssuer) {
            require(uri.query == null) {
                "PeakAuth: issuerUrl no puede contener query parameters (?): $rawUrl"
            }
        }
        val scheme = uri.scheme?.lowercase() ?: ""
        require(scheme == "https" || scheme == "http") {
            "PeakAuth: esquema de URL no válido ('$scheme'): debe ser https o http"
        }
        val host = uri.host?.lowercase() ?: ""
        if (scheme == "http") {
            if (!isLoopbackHost(host)) {
                throw SecurityException("PeakAuth: URL insegura ($rawUrl): HTTPS es obligatorio para hosts remotos; HTTP no está permitido para hosts no loopback bajo ninguna circunstancia")
            }
            if (!config.insecureAllowHttp) {
                throw SecurityException("PeakAuth: URL loopback con HTTP ($rawUrl) requiere insecureAllowHttp = true para desarrollo local controlado")
            }
        }
        return uri
    }

    internal fun parseOpenIdConfiguration(json: String): OpenIdConfiguration {
        val root = SafeJsonParser.parseObject(json)
        val issuer = SafeJsonParser.getString(root, "issuer") ?: ""
        val authEp = SafeJsonParser.getString(root, "authorization_endpoint") ?: ""
        val tokenEp = SafeJsonParser.getString(root, "token_endpoint") ?: ""
        val jwksUri = SafeJsonParser.getString(root, "jwks_uri") ?: ""
        val endSessionEp = SafeJsonParser.getString(root, "end_session_endpoint")
        val introspectEp = SafeJsonParser.getString(root, "introspection_endpoint")

        val responseTypes = SafeJsonParser.getStringList(root, "response_types_supported")
        val signingAlgs = SafeJsonParser.getStringList(root, "id_token_signing_alg_values_supported")
        val scopes = SafeJsonParser.getStringList(root, "scopes_supported")
        val codeChallengeMethods = SafeJsonParser.getStringList(root, "code_challenge_methods_supported")

        // Validar emisor y endpoints descubiertos
        val baseUri = URI(config.normalizedIssuerUrl)
        val discUri = validateEndpointUrl(issuer, true)

        val discScheme = discUri.scheme?.lowercase() ?: ""
        val baseScheme = baseUri.scheme?.lowercase() ?: ""
        if (discScheme != baseScheme) {
            throw SecurityException("PeakAuth openid-configuration: esquema del issuer ('$discScheme') no coincide con el emisor configurado ('$baseScheme')")
        }
        val discHost = discUri.host?.lowercase() ?: ""
        val baseHost = baseUri.host?.lowercase() ?: ""
        if (!discHost.equals(baseHost, ignoreCase = true)) {
            throw SecurityException("PeakAuth openid-configuration: host del issuer ('$discHost') no coincide con el emisor configurado ('$baseHost')")
        }
        if (discUri.port != baseUri.port) {
            throw SecurityException("PeakAuth openid-configuration: puerto del issuer ('${discUri.port}') no coincide con el emisor configurado ('${baseUri.port}')")
        }
        val normDiscPath = (discUri.path ?: "").trimEnd('/')
        val normBasePath = (baseUri.path ?: "").trimEnd('/')
        if (normDiscPath != normBasePath) {
            throw SecurityException("PeakAuth openid-configuration: path del issuer ('$normDiscPath') no coincide con el emisor configurado ('$normBasePath')")
        }

        val endpointsToCheck = mapOf(
            "authorization_endpoint" to authEp,
            "token_endpoint" to tokenEp,
            "jwks_uri" to jwksUri
        )
        for ((epName, epVal) in endpointsToCheck) {
            if (epVal.isBlank()) {
                throw SecurityException("PeakAuth openid-configuration: $epName es obligatorio y no puede estar vacío")
            }
            val epUri = validateEndpointUrl(epVal, false)
            val epScheme = epUri.scheme?.lowercase() ?: ""
            if (epScheme != baseScheme) {
                throw SecurityException("PeakAuth openid-configuration: esquema de $epName ('$epScheme') no coincide con el emisor ('$baseScheme')")
            }
            val epHost = epUri.host?.lowercase() ?: ""
            if (!epHost.equals(baseHost, ignoreCase = true)) {
                throw SecurityException("PeakAuth openid-configuration: host de $epName ('$epHost') no coincide con el emisor ('$baseHost')")
            }
            if (epUri.port != baseUri.port) {
                throw SecurityException("PeakAuth openid-configuration: puerto de $epName ('${epUri.port}') no coincide con el emisor ('${baseUri.port}')")
            }
        }

        return OpenIdConfiguration(
            issuer = issuer,
            authorizationEndpoint = authEp,
            tokenEndpoint = tokenEp,
            jwksUri = jwksUri,
            endSessionEndpoint = endSessionEp,
            introspectionEndpoint = introspectEp,
            responseTypesSupported = responseTypes,
            idTokenSigningAlgValuesSupported = signingAlgs,
            scopesSupported = scopes,
            codeChallengeMethodsSupported = codeChallengeMethods
        )
    }

    private fun urlEncode(value: String): String {
        return URLEncoder.encode(value, "UTF-8")
    }

    internal fun escapeJsonString(value: String): String {
        val sb = StringBuilder()
        for (c in value) {
            when (c) {
                '\\' -> sb.append("\\\\")
                '"' -> sb.append("\\\"")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> {
                    if (c < ' ') {
                        sb.append(String.format("\\u%04x", c.code))
                    } else {
                        sb.append(c)
                    }
                }
            }
        }
        return sb.toString()
    }

    internal fun buildJson(vararg pairs: Pair<String, String>): String {
        return pairs.joinToString(separator = ",", prefix = "{", postfix = "}") { (k, v) ->
            "\"${escapeJsonString(k)}\":\"${escapeJsonString(v)}\""
        }
    }
}
