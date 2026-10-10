package io.peakauth

import io.peakauth.models.PkcePair
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * Utilidad criptográfica para Proof Key for Code Exchange (PKCE - RFC 7636).
 */
object PkceHelper {
    private const val CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    private val secureRandom = SecureRandom()

    /**
     * Genera un par PKCE criptográfico (code_verifier y code_challenge).
     *
     * @param length Longitud del code_verifier (entre 43 y 128 caracteres, por defecto 64).
     */
    fun generate(length: Int = 64): PkcePair {
        require(length in 43..128) { "El code_verifier debe tener entre 43 y 128 caracteres (RFC 7636)" }

        val sb = StringBuilder(length)
        for (i in 0 until length) {
            val idx = secureRandom.nextInt(CHARACTERS.length)
            sb.append(CHARACTERS[idx])
        }
        val verifier = sb.toString()

        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(verifier.toByteArray(Charsets.US_ASCII))
        val challenge = base64UrlEncode(hash)

        return PkcePair(
            codeVerifier = verifier,
            codeChallenge = challenge,
            method = "S256"
        )
    }

    /**
     * Codifica un array de bytes en formato Base64 URL-safe sin relleno (padding).
     */
    fun base64UrlEncode(bytes: ByteArray): String {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    /**
     * Decodifica una cadena Base64 o Base64 URL-safe (con o sin padding).
     */
    fun base64UrlDecode(str: String): ByteArray {
        var normalized = str.replace('-', '+').replace('_', '/')
        while (normalized.length % 4 != 0) {
            normalized += "="
        }
        return Base64.getDecoder().decode(normalized)
    }

    /**
     * Genera un valor 'state' aleatorio criptográficamente seguro para mitigar CSRF en OAuth 2.0.
     */
    fun generateState(length: Int = 32): String {
        require(length in 16..128) { "La longitud de state debe estar entre 16 y 128 caracteres" }
        val randomBytes = ByteArray(length)
        secureRandom.nextBytes(randomBytes)
        return base64UrlEncode(randomBytes)
    }

    /**
     * Compara dos estados en tiempo constante (constant-time) para mitigar ataques de temporización.
     */
    fun validateState(expectedState: String?, actualState: String?): Boolean {
        if (expectedState.isNullOrEmpty() || actualState.isNullOrEmpty()) {
            return false
        }
        val b1 = expectedState.toByteArray(Charsets.UTF_8)
        val b2 = actualState.toByteArray(Charsets.UTF_8)
        return MessageDigest.isEqual(b1, b2)
    }
}
