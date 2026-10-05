package io.peakauth.models

/**
 * Metadatos de descubrimiento OpenID Connect devueltos por `/.well-known/openid-configuration` (RFC 8414).
 */
data class OpenIdConfiguration(
    val issuer: String,
    val authorizationEndpoint: String,
    val tokenEndpoint: String,
    val jwksUri: String,
    val endSessionEndpoint: String? = null,
    val introspectionEndpoint: String? = null,
    val responseTypesSupported: List<String> = emptyList(),
    val idTokenSigningAlgValuesSupported: List<String> = emptyList(),
    val scopesSupported: List<String> = emptyList(),
    val codeChallengeMethodsSupported: List<String> = emptyList()
)
