package io.peakauth

import io.peakauth.crypto.JwksProvider
import io.peakauth.crypto.JwtVerifier
import io.peakauth.crypto.SafeJsonParser
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class JwtVerifierTest {

    private lateinit var rsaPublicKey: RSAPublicKey
    private lateinit var rsaPrivateKey: RSAPrivateKey
    private lateinit var config: PeakAuthConfig
    private lateinit var mockJwksProvider: JwksProvider

    @BeforeEach
    fun setup() {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val kp = kpg.generateKeyPair()
        rsaPublicKey = kp.public as RSAPublicKey
        rsaPrivateKey = kp.private as RSAPrivateKey

        config = PeakAuthConfig(
            issuerUrl = "https://auth.peak.local",
            clientId = "my-test-app",
            expectedIssuer = "peak-auth"
        )

        mockJwksProvider = object : JwksProvider("https://auth.peak.local/.well-known/jwks.json") {
            override fun getKey(kid: String?): RSAPublicKey = rsaPublicKey
        }
    }

    private fun createJwt(
        sub: String = "123",
        email: String = "user@peak.local",
        username: String = "testuser",
        tokenType: String = "access",
        aud: String = "\"my-test-app\"",
        iss: String = "peak-auth",
        exp: Long = (System.currentTimeMillis() / 1000) + 3600,
        iat: Long = (System.currentTimeMillis() / 1000) - 10,
        roles: String = "[\"ADMIN\", \"USER\"]",
        kid: String = "test-key-1",
        alg: String = "RS256"
    ): String {
        val headerJson = "{\"alg\":\"$alg\",\"typ\":\"JWT\",\"kid\":\"$kid\"}"
        val payloadJson = """
            {
                "sub": "$sub",
                "email": "$email",
                "username": "$username",
                "token_type": "$tokenType",
                "aud": $aud,
                "iss": "$iss",
                "exp": $exp,
                "iat": $iat,
                "roles": $roles,
                "app_id": "my-test-app",
                "mfa_verified": true,
                "authz_version": 1,
                "given_name": "Test",
                "family_name": "User"
            }
        """.trimIndent()

        val headerB64 = PkceHelper.base64UrlEncode(headerJson.toByteArray(Charsets.UTF_8))
        val payloadB64 = PkceHelper.base64UrlEncode(payloadJson.toByteArray(Charsets.UTF_8))

        val signedData = "$headerB64.$payloadB64".toByteArray(Charsets.US_ASCII)
        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(rsaPrivateKey)
        signer.update(signedData)
        val sigBytes = signer.sign()
        val sigB64 = PkceHelper.base64UrlEncode(sigBytes)

        return "$headerB64.$payloadB64.$sigB64"
    }

    private fun createRawJwt(
        headerJson: String,
        payloadJson: String
    ): String {
        val headerB64 = PkceHelper.base64UrlEncode(headerJson.toByteArray(Charsets.UTF_8))
        val payloadB64 = PkceHelper.base64UrlEncode(payloadJson.toByteArray(Charsets.UTF_8))

        val signedData = "$headerB64.$payloadB64".toByteArray(Charsets.US_ASCII)
        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(rsaPrivateKey)
        signer.update(signedData)
        val sigBytes = signer.sign()
        val sigB64 = PkceHelper.base64UrlEncode(sigBytes)

        return "$headerB64.$payloadB64.$sigB64"
    }

    @Test
    fun `verify validates valid token signature and claims`() {
        val token = createJwt()

        val verifier = JwtVerifier(config, mockJwksProvider)

        val claims = verifier.verify(token)
        assertEquals("123", claims.sub)
        assertEquals("user@peak.local", claims.email)
        assertEquals("testuser", claims.username)
        assertEquals("testuser", claims.preferredUsername)
        assertEquals("access", claims.tokenType)
        assertEquals("peak-auth", claims.iss)
        assertTrue(claims.hasRole("ADMIN"))
        assertTrue(claims.hasRole("USER"))
        assertFalse(claims.hasRole("SUPERADMIN"))
        assertTrue(claims.mfaVerified)
        assertEquals("Test", claims.firstName)
        assertEquals("User", claims.lastName)
        assertFalse(claims.isExpired())
    }

    @Test
    fun `verify rejects token with mfa_pending token type`() {
        val token = createJwt(tokenType = "mfa_pending")
        val verifier = JwtVerifier(config, mockJwksProvider)

        val ex = assertThrows(SecurityException::class.java) {
            verifier.verify(token)
        }
        assertTrue(ex.message?.contains("Tipo de token inválido") == true)
    }

    @Test
    fun `SafeJsonParser getString returns only strings and never stringifies other types`() {
        val json = """
            {
                "str": "hello",
                "num": 123,
                "bool": true,
                "list": ["a", "b"],
                "obj": {"nested": "val"}
            }
        """.trimIndent()
        val parsed = SafeJsonParser.parseObject(json)
        assertEquals("hello", SafeJsonParser.getString(parsed, "str"))
        assertNull(SafeJsonParser.getString(parsed, "num"))
        assertNull(SafeJsonParser.getString(parsed, "bool"))
        assertNull(SafeJsonParser.getString(parsed, "list"))
        assertNull(SafeJsonParser.getString(parsed, "obj"))
        assertNull(SafeJsonParser.getString(parsed, "nonexistent"))

        // getStringList
        val mixedJson = """
            {
                "strings": ["read", "write"],
                "single": "admin",
                "mixed": ["read", 123, true, null, "write"],
                "numbers_only": [1, 2, 3]
            }
        """.trimIndent()
        val mixedParsed = SafeJsonParser.parseObject(mixedJson)
        assertEquals(listOf("read", "write"), SafeJsonParser.getStringList(mixedParsed, "strings"))
        assertEquals(listOf("admin"), SafeJsonParser.getStringList(mixedParsed, "single"))
        assertEquals(listOf("read", "write"), SafeJsonParser.getStringList(mixedParsed, "mixed"))
        assertEquals(emptyList<String>(), SafeJsonParser.getStringList(mixedParsed, "numbers_only"))
    }

    @Test
    fun `SafeJsonParser rejects invalid escapes`() {
        val invalidEscapes = listOf(
            "{\"val\":\"test\\x\"}",
            "{\"val\":\"test\\a\"}",
            "{\"val\":\"test\\0\"}",
            "{\"val\":\"test\\u12\"}",
            "{\"val\":\"test\\u12xy\"}"
        )
        for (json in invalidEscapes) {
            assertThrows(IllegalArgumentException::class.java, {
                SafeJsonParser.parse(json)
            }, "Debería rechazar escape inválido en: $json")
        }
    }

    @Test
    fun `SafeJsonParser rejects unescaped control characters in strings`() {
        val controlChars = listOf(
            "{\"val\":\"hello\u0000world\"}",
            "{\"val\":\"hello\u0009world\"}",
            "{\"val\":\"hello\nworld\"}",
            "{\"val\":\"hello\rworld\"}",
            "{\"val\":\"hello\u001Fworld\"}"
        )
        for (json in controlChars) {
            assertThrows(IllegalArgumentException::class.java, {
                SafeJsonParser.parse(json)
            }, "Debería rechazar caracteres de control sin escapar en: $json")
        }
    }

    @Test
    fun `SafeJsonParser rejects malformed numbers`() {
        val malformedNumbers = listOf(
            "{\"n\": -}",
            "{\"n\": 1.}",
            "{\"n\": 1e}",
            "{\"n\": 1e+}",
            "{\"n\": 1e-}",
            "{\"n\": 01}",
            "{\"n\": -05}",
            "{\"n\": .5}"
        )
        for (json in malformedNumbers) {
            assertThrows(IllegalArgumentException::class.java, {
                SafeJsonParser.parse(json)
            }, "Debería rechazar número malformado: $json")
        }
    }

    @Test
    fun `SafeJsonParser correctly parses valid unicode escapes and valid numbers`() {
        val json = """
            {
                "unicode": "A \u0042\u0043 \u00f1 \u20ac",
                "standard_escapes": "\" \\ \/ \b \f \n \r \t",
                "integer": 42,
                "negative": -100,
                "zero": 0,
                "fraction": 3.14159,
                "exp_upper": 1E6,
                "exp_lower": 2.5e-3
            }
        """.trimIndent()
        val parsed = SafeJsonParser.parseObject(json)
        assertEquals("A BC ñ €", SafeJsonParser.getString(parsed, "unicode"))
        assertEquals("\" \\ / \b \u000C \n \r \t", SafeJsonParser.getString(parsed, "standard_escapes"))
        assertEquals(42L, SafeJsonParser.getLong(parsed, "integer"))
        assertEquals(-100L, SafeJsonParser.getLong(parsed, "negative"))
        assertEquals(0L, SafeJsonParser.getLong(parsed, "zero"))
        assertEquals(3.14159, (parsed["fraction"] as Number).toDouble(), 0.00001)
        assertEquals(1000000.0, (parsed["exp_upper"] as Number).toDouble(), 0.01)
        assertEquals(0.0025, (parsed["exp_lower"] as Number).toDouble(), 0.0001)
    }

    @Test
    fun `verify rejects tokens with incorrect types in claims`() {
        val verifier = JwtVerifier(config, mockJwksProvider)
        val validHeader = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"test-key-1\"}"
        val exp = (System.currentTimeMillis() / 1000) + 3600

        // 1. kid no es String
        val badKidHeader = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":12345}"
        val t1 = createRawJwt(badKidHeader, "{\"sub\":\"123\",\"aud\":\"my-test-app\",\"exp\":$exp}")
        assertThrows(SecurityException::class.java) { verifier.verify(t1) }

        // 2. sub no es String
        val t2 = createRawJwt(validHeader, "{\"sub\":12345,\"aud\":\"my-test-app\",\"exp\":$exp}")
        assertThrows(SecurityException::class.java) { verifier.verify(t2) }

        // 3. iss no es String
        val t3 = createRawJwt(validHeader, "{\"sub\":\"123\",\"iss\":999,\"aud\":\"my-test-app\",\"exp\":$exp}")
        assertThrows(SecurityException::class.java) { verifier.verify(t3) }

        // 4. token_type no es String
        val t4 = createRawJwt(validHeader, "{\"sub\":\"123\",\"token_type\":123,\"aud\":\"my-test-app\",\"exp\":$exp}")
        assertThrows(SecurityException::class.java) { verifier.verify(t4) }

        // 5. email no es String
        val t5 = createRawJwt(validHeader, "{\"sub\":\"123\",\"email\":123,\"aud\":\"my-test-app\",\"exp\":$exp}")
        assertThrows(SecurityException::class.java) { verifier.verify(t5) }

        // 6. username no es String
        val t6 = createRawJwt(validHeader, "{\"sub\":\"123\",\"username\":{},\"aud\":\"my-test-app\",\"exp\":$exp}")
        assertThrows(SecurityException::class.java) { verifier.verify(t6) }

        // 7. preferred_username no es String
        val t7 = createRawJwt(validHeader, "{\"sub\":\"123\",\"preferred_username\":true,\"aud\":\"my-test-app\",\"exp\":$exp}")
        assertThrows(SecurityException::class.java) { verifier.verify(t7) }

        // 8. roles no es array de strings (string simple)
        val t8 = createRawJwt(validHeader, "{\"sub\":\"123\",\"roles\":\"ADMIN\",\"aud\":\"my-test-app\",\"exp\":$exp}")
        assertThrows(SecurityException::class.java) { verifier.verify(t8) }

        // 9. roles es array con números
        val t9 = createRawJwt(validHeader, "{\"sub\":\"123\",\"roles\":[1, 2],\"aud\":\"my-test-app\",\"exp\":$exp}")
        assertThrows(SecurityException::class.java) { verifier.verify(t9) }

        // 10. aud no es string o array de strings (número)
        val t10 = createRawJwt(validHeader, "{\"sub\":\"123\",\"aud\":123,\"exp\":$exp}")
        assertThrows(SecurityException::class.java) { verifier.verify(t10) }

        // 11. aud es array con números
        val t11 = createRawJwt(validHeader, "{\"sub\":\"123\",\"aud\":[123],\"exp\":$exp}")
        assertThrows(SecurityException::class.java) { verifier.verify(t11) }
    }

    @Test
    fun `SafeJsonParser parses empty strings and nested types accurately`() {
        val json = "{\"empty_field\":\"\",\"normal_field\":\"value\",\"num\":42,\"bool\":true}"
        val parsed = SafeJsonParser.parseObject(json)
        assertEquals("", SafeJsonParser.getString(parsed, "empty_field"))
        assertEquals("value", SafeJsonParser.getString(parsed, "normal_field"))
        assertEquals(42L, SafeJsonParser.getLong(parsed, "num"))
        assertEquals(true, SafeJsonParser.getBoolean(parsed, "bool"))
        assertNull(SafeJsonParser.getString(parsed, "non_existent"))
    }

    @Test
    fun `verify rejects tampered token`() {
        val token = createJwt()
        val parts = token.split('.').toMutableList()
        // Alterar el payload
        parts[1] = PkceHelper.base64UrlEncode("{\"sub\":\"hacked\"}".toByteArray(Charsets.UTF_8))
        val tamperedToken = parts.joinToString(".")

        val verifier = JwtVerifier(config, mockJwksProvider)

        assertThrows(SecurityException::class.java) {
            verifier.verify(tamperedToken)
        }
    }

    @Test
    fun `verify rejects expired token`() {
        val pastExp = (System.currentTimeMillis() / 1000) - 300 // Expiró hace 5 min
        val token = createJwt(exp = pastExp)

        val verifier = JwtVerifier(config, mockJwksProvider)

        assertThrows(SecurityException::class.java) {
            verifier.verify(token)
        }
    }

    @Test
    fun `verify rejects token without exp claim`() {
        val headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"k1\"}"
        val payloadJson = "{\"sub\":\"123\",\"iss\":\"peak-auth\",\"aud\":[\"my-test-app\"]}"

        val headerB64 = PkceHelper.base64UrlEncode(headerJson.toByteArray(Charsets.UTF_8))
        val payloadB64 = PkceHelper.base64UrlEncode(payloadJson.toByteArray(Charsets.UTF_8))

        val signedData = "$headerB64.$payloadB64".toByteArray(Charsets.US_ASCII)
        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(rsaPrivateKey)
        signer.update(signedData)
        val sigB64 = PkceHelper.base64UrlEncode(signer.sign())

        val tokenWithoutExp = "$headerB64.$payloadB64.$sigB64"
        val verifier = JwtVerifier(config, mockJwksProvider)

        val ex = assertThrows(SecurityException::class.java) {
            verifier.verify(tokenWithoutExp)
        }
        assertTrue(ex.message?.contains("claim 'exp' es obligatorio") == true)
    }

    @Test
    fun `verify rejects future iat`() {
        val futureIat = (System.currentTimeMillis() / 1000) + 1000
        val token = createJwt(iat = futureIat)

        val verifier = JwtVerifier(config, mockJwksProvider)
        val ex = assertThrows(SecurityException::class.java) {
            verifier.verify(token)
        }
        assertTrue(ex.message?.contains("emitido en el futuro") == true)
    }

    @Test
    fun `verify rejects non RS256 algorithm`() {
        val token = createJwt(alg = "HS256")
        val verifier = JwtVerifier(config, mockJwksProvider)

        val ex = assertThrows(SecurityException::class.java) {
            verifier.verify(token)
        }
        assertTrue(ex.message?.contains("Algoritmo 'HS256' no soportado") == true)
    }

    @Test
    fun `verify rejects wrong audience`() {
        val token = createJwt(aud = "\"another-different-app\"")
        val verifier = JwtVerifier(config, mockJwksProvider)

        assertThrows(SecurityException::class.java) {
            verifier.verify(token)
        }
    }

    @Test
    fun `verify rejects wrong issuer`() {
        val token = createJwt(iss = "malicious-issuer")
        val verifier = JwtVerifier(config, mockJwksProvider)

        assertThrows(SecurityException::class.java) {
            verifier.verify(token)
        }
    }

    @Test
    fun `parseJwks strictly validates alg, use, RSA bit length and exponent`() {
        val jwksProvider = JwksProvider("https://auth.peak.local/.well-known/jwks.json")
        val validN = PkceHelper.base64UrlEncode(rsaPublicKey.modulus.toByteArray())
        val validE = PkceHelper.base64UrlEncode(rsaPublicKey.publicExponent.toByteArray())

        val weakKpg = KeyPairGenerator.getInstance("RSA")
        weakKpg.initialize(1024)
        val weakKp = weakKpg.generateKeyPair()
        val weakN = PkceHelper.base64UrlEncode((weakKp.public as RSAPublicKey).modulus.toByteArray())

        // 1. Clave válida 2048-bit con e=65537
        val validJson = """{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"k-valid","n":"$validN","e":"$validE"}]}"""
        jwksProvider.parseJwks(validJson)
        assertTrue(jwksProvider.hasKey("k-valid"))

        // 2. alg ausente
        val noAlgJson = """{"keys":[{"kty":"RSA","use":"sig","kid":"k-no-alg","n":"$validN","e":"$validE"}]}"""
        val p2 = JwksProvider("https://auth.peak.local/.well-known/jwks.json")
        p2.parseJwks(noAlgJson)
        assertFalse(p2.hasKey("k-no-alg"))

        // 3. use ausente
        val noUseJson = """{"keys":[{"kty":"RSA","alg":"RS256","kid":"k-no-use","n":"$validN","e":"$validE"}]}"""
        val p3 = JwksProvider("https://auth.peak.local/.well-known/jwks.json")
        p3.parseJwks(noUseJson)
        assertFalse(p3.hasKey("k-no-use"))

        // 4. alg incorrecto (HS256)
        val wrongAlgJson = """{"keys":[{"kty":"RSA","alg":"HS256","use":"sig","kid":"k-wrong-alg","n":"$validN","e":"$validE"}]}"""
        val p4 = JwksProvider("https://auth.peak.local/.well-known/jwks.json")
        p4.parseJwks(wrongAlgJson)
        assertFalse(p4.hasKey("k-wrong-alg"))

        // 5. use incorrecto (enc)
        val wrongUseJson = """{"keys":[{"kty":"RSA","alg":"RS256","use":"enc","kid":"k-wrong-use","n":"$validN","e":"$validE"}]}"""
        val p5 = JwksProvider("https://auth.peak.local/.well-known/jwks.json")
        p5.parseJwks(wrongUseJson)
        assertFalse(p5.hasKey("k-wrong-use"))

        // 6. RSA de menos de 2048 bits (1024 bits)
        val weakRsaJson = """{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"k-weak","n":"$weakN","e":"$validE"}]}"""
        val p6 = JwksProvider("https://auth.peak.local/.well-known/jwks.json")
        p6.parseJwks(weakRsaJson)
        assertFalse(p6.hasKey("k-weak"))

        // 7. exponente 1
        val exp1Json = """{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"k-exp1","n":"$validN","e":"${PkceHelper.base64UrlEncode(byteArrayOf(1))}"}]}"""
        val p7 = JwksProvider("https://auth.peak.local/.well-known/jwks.json")
        p7.parseJwks(exp1Json)
        assertFalse(p7.hasKey("k-exp1"))

        // 8. exponente 2
        val exp2Json = """{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"k-exp2","n":"$validN","e":"${PkceHelper.base64UrlEncode(byteArrayOf(2))}"}]}"""
        val p8 = JwksProvider("https://auth.peak.local/.well-known/jwks.json")
        p8.parseJwks(exp2Json)
        assertFalse(p8.hasKey("k-exp2"))

        // 9. exponente par (4)
        val exp4Json = """{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"k-exp4","n":"$validN","e":"${PkceHelper.base64UrlEncode(byteArrayOf(4))}"}]}"""
        val p9 = JwksProvider("https://auth.peak.local/.well-known/jwks.json")
        p9.parseJwks(exp4Json)
        assertFalse(p9.hasKey("k-exp4"))

        // 10. exponente par (65536)
        val exp65536Json = """{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"k-exp65536","n":"$validN","e":"${PkceHelper.base64UrlEncode(byteArrayOf(1, 0, 0))}"}]}"""
        val p10 = JwksProvider("https://auth.peak.local/.well-known/jwks.json")
        p10.parseJwks(exp65536Json)
        assertFalse(p10.hasKey("k-exp65536"))

        // 11. exponente gigante/overflow (> 4 bytes)
        val expHugeJson = """{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"k-exphuge","n":"$validN","e":"${PkceHelper.base64UrlEncode(byteArrayOf(1, 2, 3, 4, 5))}"}]}"""
        val p11 = JwksProvider("https://auth.peak.local/.well-known/jwks.json")
        p11.parseJwks(expHugeJson)
        assertFalse(p11.hasKey("k-exphuge"))
    }
}
