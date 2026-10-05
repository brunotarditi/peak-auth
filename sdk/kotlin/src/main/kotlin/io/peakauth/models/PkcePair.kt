package io.peakauth.models

/**
 * Representa un par PKCE criptográfico (RFC 7636).
 *
 * @property codeVerifier Cadena secreta de alta entropía enviada en el canje de token.
 * @property codeChallenge Hash SHA-256 codificado en Base64 URL-safe sin relleno enviado en el request de autorización.
 * @property method Método de transformación criptográfica (siempre "S256").
 */
data class PkcePair(
    val codeVerifier: String,
    val codeChallenge: String,
    val method: String = "S256"
)
