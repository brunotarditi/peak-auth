package io.peakauth.crypto

import io.peakauth.PkceHelper
import java.io.BufferedReader
import java.io.InputStreamReader
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URI
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec
import java.util.concurrent.ConcurrentHashMap

/**
 * Proveedor y gestor de claves públicas JWKS (RFC 7517) con cacheo TTL en memoria y validación criptográfica estricta.
 */
open class JwksProvider(
    private val jwksUrl: String,
    private val cacheTtlMs: Long = 60 * 60 * 1000L,
    private val connectTimeoutMs: Int = 10_000,
    private val readTimeoutMs: Int = 10_000
) {
    private val keysCache = ConcurrentHashMap<String, RSAPublicKey>()
    private var lastFetchTime: Long = 0L

    /**
     * Obtiene la clave pública RSA asociada a un Key ID (kid).
     * Si la clave no está en caché o la caché expiró, consulta el endpoint JWKS.
     */
    @Synchronized
    open fun getKey(kid: String?): RSAPublicKey {
        val now = System.currentTimeMillis()
        val isCacheExpired = (now - lastFetchTime) > cacheTtlMs

        if (keysCache.isEmpty() || isCacheExpired || (kid != null && !keysCache.containsKey(kid))) {
            fetchJwks()
        }

        if (kid != null && keysCache.containsKey(kid)) {
            return keysCache[kid]!!
        }

        // Si no se especificó kid y sólo hay una clave disponible, retornar la primera
        if (kid == null && keysCache.size == 1) {
            return keysCache.values.first()
        }

        if (kid != null) {
            throw IllegalArgumentException("PeakAuth: Clave pública con kid '$kid' no encontrada en JWKS")
        }

        throw IllegalStateException("PeakAuth: Múltiples claves disponibles en JWKS pero el token no especifica 'kid'")
    }

    /**
     * Descarga el JSON de JWKS y reconstruye las instancias de [RSAPublicKey].
     */
    private fun fetchJwks() {
        val connection = (URI(jwksUrl).toURL().openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = connectTimeoutMs
            readTimeout = readTimeoutMs
            setRequestProperty("Accept", "application/json")
        }

        try {
            val responseCode = connection.responseCode
            if (responseCode !in 200..299) {
                throw IllegalStateException("PeakAuth: Error descargando JWKS desde $jwksUrl (HTTP $responseCode)")
            }

            val responseBody = BufferedReader(InputStreamReader(connection.inputStream, Charsets.UTF_8)).use {
                it.readText()
            }

            parseJwks(responseBody)
            lastFetchTime = System.currentTimeMillis()
        } finally {
            connection.disconnect()
        }
    }

    internal fun hasKey(kid: String): Boolean = keysCache.containsKey(kid)

    /**
     * Parsea el payload JSON de JWKS validando estrictamente kty, alg, use, tamaño RSA (>= 2048) y exponente.
     */
    internal fun parseJwks(jsonString: String) {
        val root = SafeJsonParser.parseObject(jsonString)
        val keyBlocks = SafeJsonParser.getObjectList(root, "keys")

        val keyFactory = KeyFactory.getInstance("RSA")
        val newKeys = mutableMapOf<String, RSAPublicKey>()

        for (block in keyBlocks) {
            val kid = SafeJsonParser.getString(block, "kid")?.trim() ?: ""
            if (kid.isEmpty()) continue

            val kty = SafeJsonParser.getString(block, "kty")
            if (kty != "RSA") continue

            val alg = SafeJsonParser.getString(block, "alg")
            if (alg != "RS256") continue

            val use = SafeJsonParser.getString(block, "use")
            if (use != "sig") continue

            val nStr = SafeJsonParser.getString(block, "n")?.trim() ?: continue
            val eStr = SafeJsonParser.getString(block, "e")?.trim() ?: continue
            if (nStr.isEmpty() || eStr.isEmpty()) continue

            val modulusBytes = try {
                PkceHelper.base64UrlDecode(nStr)
            } catch (ex: Exception) {
                continue
            }
            val exponentBytes = try {
                PkceHelper.base64UrlDecode(eStr)
            } catch (ex: Exception) {
                continue
            }

            if (exponentBytes.isEmpty() || exponentBytes.size > 4) {
                continue
            }

            val modulus = BigInteger(1, modulusBytes)
            val exponent = BigInteger(1, exponentBytes)

            // Validación de longitud mínima de clave RSA: >= 2048 bits
            if (modulus.bitLength() < 2048) {
                continue
            }

            // Exponente: entero positivo, impar, >= 3 y sin overflow (<= Int.MAX_VALUE)
            if (exponent < BigInteger.valueOf(3) ||
                !exponent.testBit(0) ||
                exponent > BigInteger.valueOf(Int.MAX_VALUE.toLong())
            ) {
                continue
            }

            val spec = RSAPublicKeySpec(modulus, exponent)
            val publicKey = keyFactory.generatePublic(spec) as RSAPublicKey

            newKeys[kid] = publicKey
        }

        if (newKeys.isNotEmpty()) {
            keysCache.clear()
            keysCache.putAll(newKeys)
        }
    }
}
