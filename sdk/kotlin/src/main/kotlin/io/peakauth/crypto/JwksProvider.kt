package io.peakauth.crypto

import io.peakauth.PkceHelper
import java.io.BufferedReader
import java.io.InputStreamReader
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec
import java.util.concurrent.ConcurrentHashMap

/**
 * Proveedor y gestor de claves públicas JWKS (RFC 7517) con cacheo TTL en memoria.
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

        // Si no se especificó kid o sólo hay una clave disponible, retornar la primera
        if (keysCache.size == 1) {
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

    /**
     * Parsea el payload JSON de JWKS sin requerir librerías externas pesadas.
     */
    private fun parseJwks(jsonString: String) {
        val keyFactory = KeyFactory.getInstance("RSA")
        val newKeys = mutableMapOf<String, RSAPublicKey>()

        // Extracción de cada bloque de clave {"kty":"RSA", ...}
        val keyBlocks = extractJsonObjects(jsonString)

        for (block in keyBlocks) {
            val kty = extractJsonStringField(block, "kty")
            if (kty != "RSA") continue

            val kid = extractJsonStringField(block, "kid") ?: ""
            val nStr = extractJsonStringField(block, "n") ?: continue
            val eStr = extractJsonStringField(block, "e") ?: continue

            val modulusBytes = PkceHelper.base64UrlDecode(nStr)
            val exponentBytes = PkceHelper.base64UrlDecode(eStr)

            val modulus = BigInteger(1, modulusBytes)
            val exponent = BigInteger(1, exponentBytes)

            val spec = RSAPublicKeySpec(modulus, exponent)
            val publicKey = keyFactory.generatePublic(spec) as RSAPublicKey

            if (kid.isNotEmpty()) {
                newKeys[kid] = publicKey
            } else {
                newKeys["default"] = publicKey
            }
        }

        if (newKeys.isNotEmpty()) {
            keysCache.clear()
            keysCache.putAll(newKeys)
        }
    }

    companion object {
        internal fun extractJsonStringField(json: String, fieldName: String): String? {
            val pattern = Regex("\"$fieldName\"\\s*:\\s*\"([^\"]*)\"")
            return pattern.find(json)?.groupValues?.get(1)
        }

        internal fun extractJsonObjects(json: String): List<String> {
            val list = mutableListOf<String>()
            var depth = 0
            var startIndex = -1

            for (i in json.indices) {
                when (json[i]) {
                    '{' -> {
                        if (depth == 1) { // Dentro del array de keys
                            startIndex = i
                        }
                        depth++
                    }
                    '}' -> {
                        depth--
                        if (depth == 1 && startIndex != -1) {
                            list.add(json.substring(startIndex, i + 1))
                            startIndex = -1
                        }
                    }
                }
            }
            return list
        }
    }
}
