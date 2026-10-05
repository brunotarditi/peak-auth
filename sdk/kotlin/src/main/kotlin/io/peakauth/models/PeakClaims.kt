package io.peakauth.models

/**
 * Claims contenidos en un JWT de acceso emitido por Peak Auth.
 * Combina especificaciones estándar de OpenID Connect (RFC 7519) con claims contextuales de Peak Auth.
 */
data class PeakClaims(
    val sub: String,
    val email: String,
    val preferredUsername: String = "",
    val roles: List<String> = emptyList(),
    val appId: String = "",
    val mfaVerified: Boolean = false,
    val authzVersion: Long = 0L,
    val firstName: String? = null,
    val lastName: String? = null,
    val avatarUrl: String? = null,
    val iss: String = "",
    val aud: List<String> = emptyList(),
    val exp: Long = 0L,
    val iat: Long = 0L,
    val customClaims: Map<String, Any?> = emptyMap()
) {
    /**
     * Comprueba si el usuario tiene un rol determinado en la aplicación.
     */
    fun hasRole(roleName: String): Boolean {
        return roles.any { it.equals(roleName, ignoreCase = true) }
    }

    /**
     * Comprueba si el token ha expirado respecto a un timestamp dado en segundos (por defecto ahora).
     * @param clockToleranceSeconds Margen de tolerancia para desviación de reloj (clock skew).
     */
    fun isExpired(clockToleranceSeconds: Long = 45L): Boolean {
        val nowSeconds = System.currentTimeMillis() / 1000
        return (exp + clockToleranceSeconds) < nowSeconds
    }
}
