package io.peakauth.models

/**
 * Respuesta devuelta por el endpoint de introspección `/api/v1/introspect` (RFC 7662).
 */
data class IntrospectionResponse(
    val active: Boolean,
    val sub: String? = null,
    val clientId: String? = null,
    val exp: Long? = null,
    val iat: Long? = null,
    val iss: String? = null,
    val roles: List<String> = emptyList(),
    val email: String? = null,
    val mfaVerified: Boolean = false,
    val authzVersion: Long? = null
)
