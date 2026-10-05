package io.peakauth

import io.peakauth.crypto.JwksProvider
import io.peakauth.crypto.JwtVerifier
import io.peakauth.models.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
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
     * Construye la URL de inicio de sesión de Peak Auth con soporte para PKCE.
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
     * Renueva el Access Token utilizando un Refresh Token.
     */
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

        val config = parseOpenIdConfiguration(responseJson)
        openIdConfigCache = Pair(config, now + (60 * 60 * 1000L))
        return config
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
                val errorDesc = JwksProvider.extractJsonStringField(responseText, "error_description")
                    ?: JwksProvider.extractJsonStringField(responseText, "error")
                    ?: "HTTP $statusCode: $responseText"
                throw RuntimeException("PeakAuth request falló ($statusCode): $errorDesc")
            }

            return responseText
        } finally {
            conn.disconnect()
        }
    }

    private fun parseTokenResponse(json: String): TokenResponse {
        val accessToken = JwksProvider.extractJsonStringField(json, "access_token")
            ?: throw IllegalStateException("PeakAuth: access_token ausente en respuesta: $json")
        val tokenType = JwksProvider.extractJsonStringField(json, "token_type") ?: "Bearer"
        val expiresIn = JwtVerifier.extractLongField(json, "expires_in") ?: 3600L
        val refreshToken = JwksProvider.extractJsonStringField(json, "refresh_token")
        val scope = JwksProvider.extractJsonStringField(json, "scope")

        return TokenResponse(
            accessToken = accessToken,
            tokenType = tokenType,
            expiresIn = expiresIn,
            refreshToken = refreshToken,
            scope = scope
        )
    }

    private fun parseIntrospectionResponse(json: String): IntrospectionResponse {
        val active = JwtVerifier.extractBooleanField(json, "active") ?: false
        val sub = JwksProvider.extractJsonStringField(json, "sub")
        val clientId = JwksProvider.extractJsonStringField(json, "client_id")
        val exp = JwtVerifier.extractLongField(json, "exp")
        val iat = JwtVerifier.extractLongField(json, "iat")
        val iss = JwksProvider.extractJsonStringField(json, "iss")
        val email = JwksProvider.extractJsonStringField(json, "email")
        val mfaVerified = JwtVerifier.extractBooleanField(json, "mfa_verified") ?: false
        val authzVersion = JwtVerifier.extractLongField(json, "authz_version")
        val roles = JwtVerifier.extractStringArray(json, "roles")

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

    private fun parseOpenIdConfiguration(json: String): OpenIdConfiguration {
        val issuer = JwksProvider.extractJsonStringField(json, "issuer") ?: ""
        val authEp = JwksProvider.extractJsonStringField(json, "authorization_endpoint") ?: ""
        val tokenEp = JwksProvider.extractJsonStringField(json, "token_endpoint") ?: ""
        val jwksUri = JwksProvider.extractJsonStringField(json, "jwks_uri") ?: ""
        val endSessionEp = JwksProvider.extractJsonStringField(json, "end_session_endpoint")
        val introspectEp = JwksProvider.extractJsonStringField(json, "introspection_endpoint")

        val responseTypes = JwtVerifier.extractStringArray(json, "response_types_supported")
        val signingAlgs = JwtVerifier.extractStringArray(json, "id_token_signing_alg_values_supported")
        val scopes = JwtVerifier.extractStringArray(json, "scopes_supported")
        val codeChallengeMethods = JwtVerifier.extractStringArray(json, "code_challenge_methods_supported")

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
