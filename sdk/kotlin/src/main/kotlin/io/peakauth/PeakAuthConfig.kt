package io.peakauth

/**
 * Configuración para el cliente [PeakAuthClient].
 *
 * @property issuerUrl URL base del servidor Peak Auth (ej: "https://auth.tuempresa.com" o "http://10.0.2.2:9009" para emulador Android).
 * @property clientId Identificador único de la aplicación registrado en Peak Auth.
 * @property clientSecret Secreto de la aplicación (requerido solo para clientes confidenciales o M2M).
 * @property redirectUri URI registrada de redirección OAuth (ej: "miapp://callback").
 * @property expectedIssuer Emisor esperado en los claims JWT (por defecto "peak-auth").
 * @property clockToleranceSeconds Margen de tolerancia para desfasaje de reloj en validación de tokens (por defecto 45 segundos).
 * @property jwksCacheTtlMs Tiempo de vida de la caché en memoria de las claves públicas JWKS (por defecto 1 hora).
 * @property connectTimeoutMs Tiempo límite de conexión HTTP en milisegundos (por defecto 10s).
 * @property readTimeoutMs Tiempo límite de lectura HTTP en milisegundos (por defecto 10s).
 * @property insecureAllowHttp Permite esquemas HTTP únicamente en entornos de desarrollo local controlado (loopback: localhost, 127.0.0.1, ::1, o 10.0.2.2 para emulador Android). Por defecto es false. Los emisores remotos siempre requieren HTTPS sin excepción (incluso si esta opción está en true).
 */
data class PeakAuthConfig(
    val issuerUrl: String,
    val clientId: String,
    val clientSecret: String? = null,
    val redirectUri: String? = null,
    val expectedIssuer: String = "peak-auth",
    val clockToleranceSeconds: Long = 45L,
    val jwksCacheTtlMs: Long = 60 * 60 * 1000L,
    val connectTimeoutMs: Int = 10_000,
    val readTimeoutMs: Int = 10_000,
    val insecureAllowHttp: Boolean = false
) {
    val normalizedIssuerUrl: String
        get() = issuerUrl.trimEnd('/')

    init {
        require(issuerUrl.isNotBlank()) { "PeakAuth: issuerUrl no puede estar vacío" }
        require(clientId.isNotBlank()) { "PeakAuth: clientId no puede estar vacío" }

        val uri = java.net.URI(normalizedIssuerUrl)
        require(uri.isAbsolute && !uri.host.isNullOrBlank()) {
            "PeakAuth: issuerUrl debe ser una URL absoluta y tener un host válido"
        }
        require(uri.userInfo == null) {
            "PeakAuth: issuerUrl no puede contener credenciales de usuario"
        }
        require(uri.fragment == null) {
            "PeakAuth: issuerUrl no puede contener fragmentos (#)"
        }
        require(uri.query == null) {
            "PeakAuth: issuerUrl no puede contener query parameters (?)"
        }

        val scheme = uri.scheme?.lowercase() ?: ""
        require(scheme == "https" || scheme == "http") {
            "PeakAuth: Esquema de issuerUrl no válido ('$scheme'): debe ser https o http"
        }

        val host = uri.host?.lowercase() ?: ""
        if (scheme == "http") {
            if (!isLoopbackHost(host)) {
                throw IllegalArgumentException("PeakAuth: issuerUrl inseguro ($issuerUrl): HTTPS es obligatorio para hosts remotos; HTTP no está permitido para hosts no loopback bajo ninguna circunstancia")
            }
            if (!insecureAllowHttp) {
                throw IllegalArgumentException("PeakAuth: issuerUrl loopback con HTTP ($issuerUrl) requiere insecureAllowHttp = true para desarrollo local controlado")
            }
        }
    }
}

internal fun isLoopbackHost(host: String): Boolean {
    val h = host.lowercase().removeSurrounding("[", "]")
    if (h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "10.0.2.2") {
        return true
    }
    val parts = h.split('.')
    if (parts.size == 4 && parts[0] == "127") {
        return parts.all { part ->
            val n = part.toIntOrNull()
            n != null && n in 0..255 && n.toString() == part
        }
    }
    return false
}
