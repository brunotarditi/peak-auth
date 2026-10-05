package io.peakauth

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.security.MessageDigest

class PkceHelperTest {

    @Test
    fun `generate produces valid verifier and challenge`() {
        val pkce = PkceHelper.generate(64)

        assertEquals(64, pkce.codeVerifier.length)
        assertEquals("S256", pkce.method)
        assertTrue(pkce.codeChallenge.isNotEmpty())
        assertFalse(pkce.codeChallenge.contains("=")) // No padding

        // Validar que el challenge coincide con el hash SHA-256 manual
        val digest = MessageDigest.getInstance("SHA-256")
        val expectedHash = digest.digest(pkce.codeVerifier.toByteArray(Charsets.US_ASCII))
        val expectedChallenge = PkceHelper.base64UrlEncode(expectedHash)

        assertEquals(expectedChallenge, pkce.codeChallenge)
    }

    @Test
    fun `generate enforces length boundaries`() {
        assertThrows(IllegalArgumentException::class.java) {
            PkceHelper.generate(42) // Demasiado corto
        }

        assertThrows(IllegalArgumentException::class.java) {
            PkceHelper.generate(129) // Demasiado largo
        }

        assertDoesNotThrow {
            PkceHelper.generate(43)
            PkceHelper.generate(128)
        }
    }

    @Test
    fun `base64Url encoding and decoding roundtrip`() {
        val original = "¡Hola Mundo desde Peak Auth Kotlin SDK! 12345"
        val bytes = original.toByteArray(Charsets.UTF_8)

        val encoded = PkceHelper.base64UrlEncode(bytes)
        assertFalse(encoded.contains('+'))
        assertFalse(encoded.contains('/'))
        assertFalse(encoded.contains('='))

        val decodedBytes = PkceHelper.base64UrlDecode(encoded)
        assertEquals(original, String(decodedBytes, Charsets.UTF_8))
    }
}
