package io.peakauth

/**
 * Interfaz para almacenar y recuperar de forma persistente y segura las credenciales de sesión.
 */
interface TokenStorage {
    fun saveTokens(accessToken: String, refreshToken: String? = null)
    fun getAccessToken(): String?
    fun getRefreshToken(): String?
    fun clear()
}

/**
 * Implementación volátil en memoria de [TokenStorage], ideal para pruebas o clientes que no persisten estado en disco.
 */
class InMemoryTokenStorage : TokenStorage {
    @Volatile
    private var accessToken: String? = null

    @Volatile
    private var refreshToken: String? = null

    override fun saveTokens(accessToken: String, refreshToken: String?) {
        this.accessToken = accessToken
        if (refreshToken != null) {
            this.refreshToken = refreshToken
        }
    }

    override fun getAccessToken(): String? = accessToken

    override fun getRefreshToken(): String? = refreshToken

    override fun clear() {
        this.accessToken = null
        this.refreshToken = null
    }
}
