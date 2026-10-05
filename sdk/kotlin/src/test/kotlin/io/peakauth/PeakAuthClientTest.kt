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
}
