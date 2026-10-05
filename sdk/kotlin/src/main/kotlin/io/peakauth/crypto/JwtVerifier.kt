package io.peakauth.crypto

import io.peakauth.PeakAuthConfig
import io.peakauth.PkceHelper
import io.peakauth.models.PeakClaims
import java.security.Signature
import java.security.interfaces.RSAPublicKey

/**
 * Validador offline de tokens JWT asimétricos (RS256) emitidos por Peak Auth.
 */
class JwtVerifier(
    private val config: PeakAuthConfig,
    private val jwksProvider: JwksProvider
) {
    /**
     * Valida la firma RS256, expiración, emisor y audiencia del JWT.
     *
     * @param tokenString Token JWT compacto en formato `header.payload.signature`.
     * @return [PeakClaims] con la información del usuario si el token es válido.
     * @throws SecurityException si la firma es inválida, expiró o no coincide la audiencia.
     */
    fun verify(tokenString: String): PeakClaims {
        val parts = tokenString.trim().split('.')
        if (parts.size != 3) {
            throw IllegalArgumentException("PeakAuth: Formato de token JWT inválido (se esperaban 3 partes separadas por puntos)")
        }

        val headerJson = String(PkceHelper.base64UrlDecode(parts[0]), Charsets.UTF_8)
        val payloadJson = String(PkceHelper.base64UrlDecode(parts[1]), Charsets.UTF_8)
        val signatureBytes = PkceHelper.base64UrlDecode(parts[2])

        // 1. Validar Algoritmo en Header
        val alg = JwksProvider.extractJsonStringField(headerJson, "alg")
        if (alg != "RS256") {
            throw SecurityException("PeakAuth: Algoritmo '$alg' no soportado (se requiere RS256)")
        }

        val kid = JwksProvider.extractJsonStringField(headerJson, "kid")

        // 2. Obtener clave pública RSA
        val publicKey: RSAPublicKey = jwksProvider.getKey(kid)

        // 3. Validar Firma Criptográfica SHA256withRSA
        val signedData = "${parts[0]}.${parts[1]}".toByteArray(Charsets.US_ASCII)
        val verifier = Signature.getInstance("SHA256withRSA")
        verifier.initVerify(publicKey)
        verifier.update(signedData)

        if (!verifier.verify(signatureBytes)) {
            throw SecurityException("PeakAuth: Firma JWT inválida o alterada")
        }

        // 4. Parsear Claims y Validar Reglas de Seguridad
        return parseAndValidateClaims(payloadJson)
    }

    private fun parseAndValidateClaims(payloadJson: String): PeakClaims {
        val sub = JwksProvider.extractJsonStringField(payloadJson, "sub")
            ?: throw SecurityException("PeakAuth: Token inválido (claim 'sub' ausente)")

        val iss = JwksProvider.extractJsonStringField(payloadJson, "iss") ?: ""
        if (config.expectedIssuer.isNotBlank() && iss != config.expectedIssuer) {
            throw SecurityException("PeakAuth: Emisor inválido '$iss' (se esperaba '${config.expectedIssuer}')")
        }

        val audList = extractAudience(payloadJson)
        if (config.clientId.isNotBlank() && !audList.contains(config.clientId)) {
            throw SecurityException("PeakAuth: Audiencia inválida $audList (se esperaba '${config.clientId}')")
        }

        val exp = extractLongField(payloadJson, "exp") ?: 0L
        val nowSeconds = System.currentTimeMillis() / 1000L
        if (exp > 0 && (exp + config.clockToleranceSeconds) < nowSeconds) {
            throw SecurityException("PeakAuth: El token ha expirado (exp: $exp, ahora: $nowSeconds)")
        }

        val iat = extractLongField(payloadJson, "iat") ?: 0L
        val email = JwksProvider.extractJsonStringField(payloadJson, "email") ?: ""
        val preferredUsername = JwksProvider.extractJsonStringField(payloadJson, "preferred_username") ?: ""
        val appId = JwksProvider.extractJsonStringField(payloadJson, "app_id") ?: ""
        val authzVersion = extractLongField(payloadJson, "authz_version") ?: 0L
        val mfaVerified = extractBooleanField(payloadJson, "mfa_verified") ?: false

        val roles = extractStringArray(payloadJson, "roles")

        // Perfil OIDC opcional
        val firstName = JwksProvider.extractJsonStringField(payloadJson, "given_name")
            ?: JwksProvider.extractJsonStringField(payloadJson, "first_name")
        val lastName = JwksProvider.extractJsonStringField(payloadJson, "family_name")
            ?: JwksProvider.extractJsonStringField(payloadJson, "last_name")
        val avatarUrl = JwksProvider.extractJsonStringField(payloadJson, "picture")
            ?: JwksProvider.extractJsonStringField(payloadJson, "avatar_url")

        return PeakClaims(
            sub = sub,
            email = email,
            preferredUsername = preferredUsername,
            roles = roles,
            appId = appId,
            mfaVerified = mfaVerified,
            authzVersion = authzVersion,
            firstName = firstName,
            lastName = lastName,
            avatarUrl = avatarUrl,
            iss = iss,
            aud = audList,
            exp = exp,
            iat = iat
        )
    }

    companion object {
        internal fun extractLongField(json: String, fieldName: String): Long? {
            val pattern = Regex("\"$fieldName\"\\s*:\\s*([0-9]+)")
            return pattern.find(json)?.groupValues?.get(1)?.toLongOrNull()
        }

        internal fun extractBooleanField(json: String, fieldName: String): Boolean? {
            val pattern = Regex("\"$fieldName\"\\s*:\\s*(true|false)", RegexOption.IGNORE_CASE)
            return pattern.find(json)?.groupValues?.get(1)?.toBooleanStrictOrNull()
        }

        internal fun extractStringArray(json: String, fieldName: String): List<String> {
            val pattern = Regex("\"$fieldName\"\\s*:\\s*\\[([^\\]]*)\\]")
            val match = pattern.find(json) ?: return emptyList()
            val arrayContent = match.groupValues[1]

            val itemPattern = Regex("\"([^\"]+)\"")
            return itemPattern.findAll(arrayContent).map { it.groupValues[1] }.toList()
        }

        internal fun extractAudience(json: String): List<String> {
            // aud puede ser un string ("aud": "my-client") o un array ("aud": ["my-client", ...])
            val singlePattern = Regex("\"aud\"\\s*:\\s*\"([^\"]+)\"")
            val singleMatch = singlePattern.find(json)
            if (singleMatch != null) {
                return listOf(singleMatch.groupValues[1])
            }
            return extractStringArray(json, "aud")
        }
    }
}
