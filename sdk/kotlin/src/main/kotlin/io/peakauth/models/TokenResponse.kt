package io.peakauth.models

/**
 * Respuesta devuelta por Peak Auth en los endpoints `/oauth/token` y `/api/v1/refresh` (RFC 6749).
 */
data class TokenResponse(
    val accessToken: String,
    val tokenType: String = "Bearer",
    val expiresIn: Long = 3600L,
    val refreshToken: String? = null,
    val scope: String? = null
)
