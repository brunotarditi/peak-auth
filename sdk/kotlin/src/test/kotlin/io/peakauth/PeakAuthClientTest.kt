package io.peakauth

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class PeakAuthClientTest {

    @Test
    fun `getAuthorizationUrl builds correct url with PKCE and state`() {
        val config = PeakAuthConfig(
            issuerUrl = "https://auth.peak.local",
            clientId = "my-client-app",
            redirectUri = "myapp://callback"
        )
        val client = PeakAuthClient(config)

        val url = client.getAuthorizationUrl(
            state = "random-state-123",
            codeChallenge = "challenge-abc",
            scope = "openid profile"
        )

        assertTrue(url.startsWith("https://auth.peak.local/oauth/authorize?"))
        assertTrue(url.contains("client_id=my-client-app"))
        assertTrue(url.contains("redirect_uri=myapp%3A%2F%2Fcallback"))
        assertTrue(url.contains("response_type=code"))
        assertTrue(url.contains("state=random-state-123"))
        assertTrue(url.contains("code_challenge=challenge-abc"))
        assertTrue(url.contains("code_challenge_method=S256"))
        assertTrue(url.contains("scope=openid+profile") || url.contains("scope=openid%20profile"))
    }

    @Test
    fun `getAuthorizationUrl and exchangeCode enforce PKCE on public client`() {
        val publicConfig = PeakAuthConfig(
            issuerUrl = "https://auth.peak.local",
            clientId = "my-client-app",
            redirectUri = "myapp://callback"
            // Sin clientSecret
        )
        val client = PeakAuthClient(publicConfig)

        // getAuthorizationUrl debe fallar sin codeChallenge
        val ex1 = assertThrows(IllegalArgumentException::class.java) {
            client.getAuthorizationUrl(state = "state-1")
        }
        assertTrue(ex1.message?.contains("code_challenge es obligatorio para clientes públicos") == true)

        // exchangeCode debe fallar sin codeVerifier
        val ex2 = assertThrows(IllegalArgumentException::class.java) {
            client.exchangeCode(code = "auth-code")
        }
        assertTrue(ex2.message?.contains("code_verifier es obligatorio para clientes públicos") == true)
    }

    @Test
    fun `transport security enforces HTTPS on remote issuers and allows loopback`() {
        // 1. Remoto inseguro debe fallar siempre
        assertThrows(IllegalArgumentException::class.java) {
            PeakAuthConfig(issuerUrl = "http://auth.remota.com", clientId = "app")
        }

        // 2. Remoto con insecureAllowHttp = true DEBE FALLAR TAMBIÉN (HTTP remoto nunca permitido)
        val exRemote = assertThrows(IllegalArgumentException::class.java) {
            PeakAuthConfig(
                issuerUrl = "http://auth.remota.com",
                clientId = "app",
                insecureAllowHttp = true
            )
        }
        assertTrue(exRemote.message?.contains("HTTPS es obligatorio para hosts remotos") == true)

        // 3. Loopbacks sin insecureAllowHttp deben fallar
        val loopbacks = listOf("http://localhost:8080", "http://127.0.0.1:9009", "http://127.0.0.2:8080", "http://[::1]:8080", "http://10.0.2.2:8080")
        for (lb in loopbacks) {
            val exLb = assertThrows(IllegalArgumentException::class.java) {
                PeakAuthConfig(issuerUrl = lb, clientId = "app")
            }
            assertTrue(exLb.message?.contains("requiere insecureAllowHttp = true") == true)
        }

        // 4. Loopbacks con insecureAllowHttp = true deben permitirse
        for (lb in loopbacks) {
            val config = PeakAuthConfig(issuerUrl = lb, clientId = "app", insecureAllowHttp = true)
            assertNotNull(config)
        }

        // 5. Rechazar subdominios y direcciones IP privadas genéricas (incluso con insecureAllowHttp = true)
        val rejectedNonLoopbacks = listOf(
            "http://foo.localhost:8080",
            "http://app.localhost:9000",
            "http://10.1.2.3:8080",
            "http://192.168.1.1:8080",
            "http://172.16.0.1:8080"
        )
        for (badHost in rejectedNonLoopbacks) {
            val ex = assertThrows(IllegalArgumentException::class.java) {
                PeakAuthConfig(issuerUrl = badHost, clientId = "app", insecureAllowHttp = true)
            }
            assertTrue(ex.message?.contains("HTTPS es obligatorio para hosts remotos") == true, "Debería rechazar $badHost")
        }

        // 6. URLs con credenciales, fragments o queries en issuerUrl deben fallar
        val badUrls = listOf(
            "https://user:pass@auth.remota.com",
            "http://user:pass@localhost:8080",
            "https://auth.remota.com#fragment",
            "https://auth.remota.com?param=value",
            "ftp://auth.remota.com"
        )
        for (bu in badUrls) {
            assertThrows(IllegalArgumentException::class.java) {
                PeakAuthConfig(issuerUrl = bu, clientId = "app", insecureAllowHttp = true)
            }
        }
    }

    @Test
    fun `parseOpenIdConfiguration strictly validates issuer and endpoints`() {
        val config = PeakAuthConfig(
            issuerUrl = "https://auth.peak.local",
            clientId = "my-client-app"
        )
        val client = PeakAuthClient(config)

        // 1. Host mismatch
        val hostMismatch = """{
            "issuer": "https://attacker.com",
            "authorization_endpoint": "https://auth.peak.local/oauth/authorize",
            "token_endpoint": "https://auth.peak.local/oauth/token",
            "jwks_uri": "https://auth.peak.local/.well-known/jwks.json"
        }"""
        assertThrows(SecurityException::class.java) {
            client.parseOpenIdConfiguration(hostMismatch)
        }

        // 2. Scheme mismatch (http vs https)
        val schemeMismatch = """{
            "issuer": "http://auth.peak.local",
            "authorization_endpoint": "https://auth.peak.local/oauth/authorize",
            "token_endpoint": "https://auth.peak.local/oauth/token",
            "jwks_uri": "https://auth.peak.local/.well-known/jwks.json"
        }"""
        assertThrows(SecurityException::class.java) {
            client.parseOpenIdConfiguration(schemeMismatch)
        }

        // 3. Port mismatch
        val portMismatch = """{
            "issuer": "https://auth.peak.local:8443",
            "authorization_endpoint": "https://auth.peak.local/oauth/authorize",
            "token_endpoint": "https://auth.peak.local/oauth/token",
            "jwks_uri": "https://auth.peak.local/.well-known/jwks.json"
        }"""
        assertThrows(SecurityException::class.java) {
            client.parseOpenIdConfiguration(portMismatch)
        }

        // 4. Path mismatch
        val pathMismatch = """{
            "issuer": "https://auth.peak.local/other-tenant",
            "authorization_endpoint": "https://auth.peak.local/oauth/authorize",
            "token_endpoint": "https://auth.peak.local/oauth/token",
            "jwks_uri": "https://auth.peak.local/.well-known/jwks.json"
        }"""
        assertThrows(SecurityException::class.java) {
            client.parseOpenIdConfiguration(pathMismatch)
        }

        // 5. Issuer con query parameter
        val queryMismatch = """{
            "issuer": "https://auth.peak.local?bad=param",
            "authorization_endpoint": "https://auth.peak.local/oauth/authorize",
            "token_endpoint": "https://auth.peak.local/oauth/token",
            "jwks_uri": "https://auth.peak.local/.well-known/jwks.json"
        }"""
        assertThrows(IllegalArgumentException::class.java) {
            client.parseOpenIdConfiguration(queryMismatch)
        }

        // 6. authorization_endpoint vacío
        val emptyAuthEp = """{
            "issuer": "https://auth.peak.local",
            "authorization_endpoint": "",
            "token_endpoint": "https://auth.peak.local/oauth/token",
            "jwks_uri": "https://auth.peak.local/.well-known/jwks.json"
        }"""
        assertThrows(SecurityException::class.java) {
            client.parseOpenIdConfiguration(emptyAuthEp)
        }

        // 7. token_endpoint relativo
        val relativeEp = """{
            "issuer": "https://auth.peak.local",
            "authorization_endpoint": "https://auth.peak.local/oauth/authorize",
            "token_endpoint": "/oauth/token",
            "jwks_uri": "https://auth.peak.local/.well-known/jwks.json"
        }"""
        assertThrows(IllegalArgumentException::class.java) {
            client.parseOpenIdConfiguration(relativeEp)
        }

        // 8. jwks_uri remoto HTTP inseguro
        val httpJwks = """{
            "issuer": "https://auth.peak.local",
            "authorization_endpoint": "https://auth.peak.local/oauth/authorize",
            "token_endpoint": "https://auth.peak.local/oauth/token",
            "jwks_uri": "http://auth.peak.local/.well-known/jwks.json"
        }"""
        assertThrows(SecurityException::class.java) {
            client.parseOpenIdConfiguration(httpJwks)
        }
    }

    @Test
    fun `state generation and timing-safe validation`() {
        val s1 = PkceHelper.generateState()
        val s2 = PkceHelper.generateState()
        assertTrue(s1.isNotEmpty() && s2.isNotEmpty())
        assertNotEquals(s1, s2)

        assertTrue(PkceHelper.validateState(s1, s1))
        assertFalse(PkceHelper.validateState(s1, s2))
        assertFalse(PkceHelper.validateState(s1, ""))
        assertFalse(PkceHelper.validateState("", s1))
    }

    @Test
    fun `getLogoutUrl builds correct url with postLogoutRedirectUri`() {
        val config = PeakAuthConfig(
            issuerUrl = "https://auth.peak.local",
            clientId = "my-client-app",
            redirectUri = "myapp://callback"
        )
        val client = PeakAuthClient(config)

        val logoutUrl = client.getLogoutUrl(
            postLogoutRedirectUri = "myapp://logged-out",
            state = "logout-state"
        )

        assertTrue(logoutUrl.startsWith("https://auth.peak.local/oauth/logout?"))
        assertTrue(logoutUrl.contains("client_id=my-client-app"))
        assertTrue(logoutUrl.contains("post_logout_redirect_uri=myapp%3A%2F%2Flogged-out"))
        assertTrue(logoutUrl.contains("state=logout-state"))
    }

    @Test
    fun `inMemoryTokenStorage manages tokens correctly`() {
        val storage = InMemoryTokenStorage()
        assertNull(storage.getAccessToken())
        assertNull(storage.getRefreshToken())

        storage.saveTokens("access-123", "refresh-456")
        assertEquals("access-123", storage.getAccessToken())
        assertEquals("refresh-456", storage.getRefreshToken())

        storage.saveTokens("new-access")
        assertEquals("new-access", storage.getAccessToken())
        assertEquals("refresh-456", storage.getRefreshToken()) // Conserva refresh previo

        storage.clear()
        assertNull(storage.getAccessToken())
        assertNull(storage.getRefreshToken())
    }

    @Test
    fun `config rejects invalid issuer or clientId`() {
        assertThrows(IllegalArgumentException::class.java) {
            PeakAuthConfig(issuerUrl = "", clientId = "client-1")
        }

        assertThrows(IllegalArgumentException::class.java) {
            PeakAuthConfig(issuerUrl = "https://auth.peak.local", clientId = "")
        }
    }

    @Test
    fun `buildJson properly escapes quotes and backslashes`() {
        val config = PeakAuthConfig(
            issuerUrl = "https://auth.peak.local",
            clientId = "my-client-app"
        )
        val client = PeakAuthClient(config)

        val json = client.buildJson(
            "token" to "abc\"def\\ghi\njkl",
            "empty" to ""
        )

        assertEquals("{\"token\":\"abc\\\"def\\\\ghi\\njkl\",\"empty\":\"\"}", json)
    }
}
