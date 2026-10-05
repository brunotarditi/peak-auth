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
    val readTimeoutMs: Int = 10_000
) {
    val normalizedIssuerUrl: String
        get() = issuerUrl.trimEnd('/')

    init {
        require(issuerUrl.isNotBlank()) { "PeakAuth: issuerUrl no puede estar vacío" }
        require(clientId.isNotBlank()) { "PeakAuth: clientId no puede estar vacío" }
    }
}
