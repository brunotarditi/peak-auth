package io.peakauth

import io.peakauth.crypto.JwksProvider
import io.peakauth.crypto.JwtVerifier
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

        // Mock JwksProvider que retorna directamente la clave pública generada
        mockJwksProvider = object : JwksProvider("https://auth.peak.local/.well-known/jwks.json") {
            fun getMockKey(): RSAPublicKey = rsaPublicKey
        }
    }

    private fun createJwt(
        sub: String = "123",
        email: String = "user@peak.local",
        aud: String = "\"my-test-app\"",
        iss: String = "peak-auth",
        exp: Long = (System.currentTimeMillis() / 1000) + 3600,
        roles: String = "[\"ADMIN\", \"USER\"]",
        kid: String = "test-key-1"
    ): String {
        val headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"$kid\"}"
        val payloadJson = """
            {
                "sub": "$sub",
                "email": "$email",
                "preferred_username": "testuser",
                "aud": $aud,
                "iss": "$iss",
                "exp": $exp,
                "iat": ${exp - 3600},
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

    @Test
    fun `verify validates valid token signature and claims`() {
        val token = createJwt()

        // Creamos un verifier que usa nuestra mock key
        val customJwks = object : JwksProvider("https://dummy") {
            override fun getKey(kid: String?): RSAPublicKey = rsaPublicKey
        }
        val verifier = JwtVerifier(config, customJwks)

        val claims = verifier.verify(token)
        assertEquals("123", claims.sub)
        assertEquals("user@peak.local", claims.email)
        assertEquals("testuser", claims.preferredUsername)
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
    fun `verify rejects tampered token`() {
        val token = createJwt()
        val parts = token.split('.').toMutableList()
        // Alterar el payload
        parts[1] = PkceHelper.base64UrlEncode("{\"sub\":\"hacked\"}".toByteArray(Charsets.UTF_8))
        val tamperedToken = parts.joinToString(".")

        val customJwks = object : JwksProvider("https://dummy") {
            override fun getKey(kid: String?): RSAPublicKey = rsaPublicKey
        }
        val verifier = JwtVerifier(config, customJwks)

        assertThrows(SecurityException::class.java) {
            verifier.verify(tamperedToken)
        }
    }

    @Test
    fun `verify rejects expired token`() {
        val pastExp = (System.currentTimeMillis() / 1000) - 300 // Expiró hace 5 min
        val token = createJwt(exp = pastExp)

        val customJwks = object : JwksProvider("https://dummy") {
            override fun getKey(kid: String?): RSAPublicKey = rsaPublicKey
        }
        val verifier = JwtVerifier(config, customJwks)

        assertThrows(SecurityException::class.java) {
            verifier.verify(token)
        }
    }

    @Test
    fun `verify rejects wrong audience`() {
        val token = createJwt(aud = "\"another-different-app\"")

        val customJwks = object : JwksProvider("https://dummy") {
            override fun getKey(kid: String?): RSAPublicKey = rsaPublicKey
        }
        val verifier = JwtVerifier(config, customJwks)

        assertThrows(SecurityException::class.java) {
            verifier.verify(token)
        }
    }

    @Test
    fun `verify rejects wrong issuer`() {
        val token = createJwt(iss = "malicious-issuer")

        val customJwks = object : JwksProvider("https://dummy") {
            override fun getKey(kid: String?): RSAPublicKey = rsaPublicKey
        }
        val verifier = JwtVerifier(config, customJwks)

        assertThrows(SecurityException::class.java) {
            verifier.verify(token)
        }
    }
}
