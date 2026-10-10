package io.peakauth.crypto

import io.peakauth.PeakAuthConfig
import io.peakauth.PkceHelper
import io.peakauth.models.PeakClaims
import java.security.Signature
import java.security.interfaces.RSAPublicKey

/**
 * Validador offline de tokens JWT asimétricos (RS256) emitidos por Peak Auth.
 * Utiliza [SafeJsonParser] para parsear cabeceras y claims sin dependencias externas ni expresiones regulares.
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

        // 1. Validar Algoritmo y Header con SafeJsonParser
        val headerMap = SafeJsonParser.parseObject(headerJson)
        val rawAlg = headerMap["alg"]
        if (rawAlg !is String || rawAlg != "RS256") {
            throw SecurityException("PeakAuth: Algoritmo '$rawAlg' no soportado (se requiere RS256)")
        }

        val rawKid = headerMap["kid"]
        if (rawKid !is String || rawKid.trim().isEmpty()) {
            throw SecurityException("PeakAuth: Header del token no incluye 'kid' válido de tipo String")
        }
        val kid = rawKid.trim()

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
        val payloadMap = SafeJsonParser.parseObject(payloadJson)

        val rawSub = payloadMap["sub"]
        if (rawSub !is String || rawSub.isBlank()) {
            throw SecurityException("PeakAuth: Token inválido (claim 'sub' ausente o no es de tipo String)")
        }
        val sub = rawSub

        val rawIss = payloadMap["iss"]
        if (rawIss != null && rawIss !is String) {
            throw SecurityException("PeakAuth: Claim 'iss' debe ser de tipo String")
        }
        val iss = (rawIss as? String) ?: ""
        if (config.expectedIssuer.isNotBlank() && iss != config.expectedIssuer) {
            throw SecurityException("PeakAuth: Emisor inválido '$iss' (se esperaba '${config.expectedIssuer}')")
        }

        val rawAud = payloadMap["aud"]
        val audList: List<String> = when (rawAud) {
            null -> emptyList()
            is String -> listOf(rawAud)
            is List<*> -> {
                if (rawAud.any { it !is String }) {
                    throw SecurityException("PeakAuth: Claim 'aud' array contiene elementos que no son String")
                }
                @Suppress("UNCHECKED_CAST")
                rawAud as List<String>
            }
            else -> throw SecurityException("PeakAuth: Claim 'aud' debe ser un string o array de strings")
        }
        if (config.clientId.isNotBlank() && !audList.contains(config.clientId)) {
            throw SecurityException("PeakAuth: Audiencia inválida $audList (se esperaba '${config.clientId}')")
        }

        // Claim exp es obligatorio
        val rawExp = payloadMap["exp"]
        if (rawExp !is Number) {
            throw SecurityException("PeakAuth: Token inválido (claim 'exp' es obligatorio y debe ser numérico)")
        }
        val exp = rawExp.toLong()

        val nowSeconds = System.currentTimeMillis() / 1000L
        if ((exp + config.clockToleranceSeconds) < nowSeconds) {
            throw SecurityException("PeakAuth: El token ha expirado (exp: $exp, ahora: $nowSeconds)")
        }

        // Validar nbf si está presente
        val rawNbf = payloadMap["nbf"]
        if (rawNbf != null && rawNbf !is Number) {
            throw SecurityException("PeakAuth: Claim 'nbf' debe ser numérico")
        }
        val nbf = (rawNbf as? Number)?.toLong()
        if (nbf != null && (nowSeconds + config.clockToleranceSeconds) < nbf) {
            throw SecurityException("PeakAuth: Token aún no válido (nbf: $nbf, ahora: $nowSeconds)")
        }

        // Validar iat si está presente
        val rawIat = payloadMap["iat"]
        if (rawIat != null && rawIat !is Number) {
            throw SecurityException("PeakAuth: Claim 'iat' debe ser numérico")
        }
        val iat = (rawIat as? Number)?.toLong() ?: 0L
        if (iat > 0 && iat > (nowSeconds + config.clockToleranceSeconds)) {
            throw SecurityException("PeakAuth: Token inválido (claim 'iat' emitido en el futuro: $iat, ahora: $nowSeconds)")
        }

        val rawTokenType = payloadMap["token_type"]
        if (rawTokenType != null && rawTokenType !is String) {
            throw SecurityException("PeakAuth: Claim 'token_type' debe ser de tipo String")
        }
        val tokenType = (rawTokenType as? String) ?: "access"
        if (tokenType != "access") {
            throw SecurityException("PeakAuth: Tipo de token inválido '$tokenType' (se esperaba 'access')")
        }

        val rawEmail = payloadMap["email"]
        if (rawEmail != null && rawEmail !is String) {
            throw SecurityException("PeakAuth: Claim 'email' debe ser de tipo String")
        }
        val email = (rawEmail as? String) ?: ""

        val rawUsername = payloadMap["username"]
        if (rawUsername != null && rawUsername !is String) {
            throw SecurityException("PeakAuth: Claim 'username' debe ser de tipo String")
        }
        val rawPreferredUsername = payloadMap["preferred_username"]
        if (rawPreferredUsername != null && rawPreferredUsername !is String) {
            throw SecurityException("PeakAuth: Claim 'preferred_username' debe ser de tipo String")
        }
        val username = (rawUsername as? String)
            ?: (rawPreferredUsername as? String)
            ?: ""
        val preferredUsername = (rawPreferredUsername as? String)
            ?: username

        val rawAppId = payloadMap["app_id"]
        if (rawAppId != null && rawAppId !is String) {
            throw SecurityException("PeakAuth: Claim 'app_id' debe ser de tipo String")
        }
        val appId = (rawAppId as? String) ?: ""

        val rawAuthz = payloadMap["authz_version"]
        if (rawAuthz != null && rawAuthz !is Number) {
            throw SecurityException("PeakAuth: Claim 'authz_version' debe ser numérico")
        }
        val authzVersion = (rawAuthz as? Number)?.toLong() ?: 0L

        val rawMfa = payloadMap["mfa_verified"]
        if (rawMfa != null && rawMfa !is Boolean) {
            throw SecurityException("PeakAuth: Claim 'mfa_verified' debe ser booleano")
        }
        val mfaVerified = (rawMfa as? Boolean) ?: false

        val rawRoles = payloadMap["roles"]
        val roles: List<String> = when (rawRoles) {
            null -> emptyList()
            is List<*> -> {
                if (rawRoles.any { it !is String }) {
                    throw SecurityException("PeakAuth: Claim 'roles' contiene elementos que no son String")
                }
                @Suppress("UNCHECKED_CAST")
                rawRoles as List<String>
            }
            else -> throw SecurityException("PeakAuth: Claim 'roles' debe ser un array de strings")
        }

        // Perfil OIDC opcional
        val firstName = SafeJsonParser.getString(payloadMap, "given_name")
            ?: SafeJsonParser.getString(payloadMap, "first_name")
        val lastName = SafeJsonParser.getString(payloadMap, "family_name")
            ?: SafeJsonParser.getString(payloadMap, "last_name")
        val avatarUrl = SafeJsonParser.getString(payloadMap, "picture")
            ?: SafeJsonParser.getString(payloadMap, "avatar_url")

        return PeakClaims(
            sub = sub,
            email = email,
            username = username,
            preferredUsername = preferredUsername,
            tokenType = tokenType,
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
}
