# Peak Auth - SDK Oficial para Kotlin y Android 📱🛡️

SDK oficial y ultra-liviano de **Peak Auth** para **Kotlin** y **Android**. Diseñado con cero dependencias pesadas, este paquete permite implementar flujos seguros de **OAuth 2.0 con PKCE (RFC 7636)**, validación offline de **JWT asimétrico (RS256)** y gestión segura de sesiones en aplicaciones móviles nativas y Compose Multiplatform.

---

## Características Principales

- ✅ **OAuth 2.0 con PKCE (S256)**: Protección nativa contra interceptación de códigos en Android (RFC 7636).
- ✅ **Validación Offline de JWT (RS256)**: Comprobación criptográfica de firma con claves públicas descargadas de `/.well-known/jwks.json` y cacheadas en memoria.
- ✅ **Cero Dependencias Pesadas**: Criptografía basada 100% en `java.security` estándar de Java/Android.
- ✅ **Renovación Rotativa de Tokens**: Soporte nativo para refresco continuo de sesiones con `/api/v1/refresh`.
- ✅ **Introspección y OIDC Discovery**: Consulta de metadatos en `/.well-known/openid-configuration` e introspección en `/api/v1/introspect`.
- ✅ **Almacenamiento Seguro**: Interfaz `TokenStorage` lista para conectar con `EncryptedSharedPreferences` de Android Jetpack Security.
- ✅ **Federated Logout**: Cierre de sesión centralizado con prevención de Open-Redirect.

---

## Instalación

En tu archivo `build.gradle.kts` (módulo de la app):

```kotlin
dependencies {
    implementation("io.peakauth:peak-auth-kotlin:1.0.0")

    // Opcional para Android: Almacenamiento seguro
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    // Opcional para Android: Pestañas personalizadas de navegador
    implementation("androidx.browser:browser:1.8.0")
}
```

---

## 1. Inicialización

```kotlin
import io.peakauth.PeakAuthClient
import io.peakauth.PeakAuthConfig

val config = PeakAuthConfig(
    issuerUrl = "https://auth.tuempresa.com", // o "http://10.0.2.2:9009" en emulador Android
    clientId = "mi-app-android",
    redirectUri = "miapp://callback",
    expectedIssuer = "peak-auth"
)

val authClient = PeakAuthClient(config)
```

---

## 2. Flujo Completo en Android (Deep Link / Custom Tabs)

### Paso A: Configurar el `AndroidManifest.xml`

Permite que tu Activity capture la redirección de Peak Auth:

```xml
<activity
    android:name=".AuthCallbackActivity"
    android:exported="true"
    android:launchMode="singleTask">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data
            android:scheme="miapp"
            android:host="callback" />
    </intent-filter>
</activity>
```

---

### Paso B: Iniciar el Login con PKCE

```kotlin
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import io.peakauth.PkceHelper

class LoginViewModel(private val authClient: PeakAuthClient) {
    var currentPkceVerifier: String? = null

    fun startLogin(context: Context) {
        // 1. Generar PKCE criptográfico
        val pkce = authClient.generatePkce()
        currentPkceVerifier = pkce.codeVerifier

        // 2. Construir la URL de autorización
        val authUrl = authClient.getAuthorizationUrl(
            state = UUID.randomUUID().toString(),
            codeChallenge = pkce.codeChallenge,
            scope = "openid profile email"
        )

        // 3. Abrir en Chrome Custom Tabs para mantener sesión SSO
        val customTabsIntent = CustomTabsIntent.Builder().build()
        customTabsIntent.launchUrl(context, Uri.parse(authUrl))
    }
}
```

---

### Paso C: Recibir el Código y Canjear el Token

En tu `AuthCallbackActivity`:

```kotlin
class AuthCallbackActivity : AppCompatActivity() {

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        handleAuthRedirect(intent?.data)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleAuthRedirect(intent?.data)
    }

    private fun handleAuthRedirect(uri: Uri?) {
        if (uri == null || uri.scheme != "miapp") return

        val code = uri.getQueryParameter("code")
        val error = uri.getQueryParameter("error")

        if (error != null) {
            val errorDesc = uri.getQueryParameter("error_description") ?: error
            Toast.makeText(this, "Error de login: $errorDesc", Toast.LENGTH_LONG).show()
            return
        }

        if (code != null) {
            lifecycleScope.launch(Dispatchers.IO) {
                try {
                    // Canje de código por Token mediante PKCE
                    val tokenResponse = authClient.exchangeCode(
                        code = code,
                        codeVerifier = viewModel.currentPkceVerifier
                    )

                    // Validación offline de JWT (RS256)
                    val claims = authClient.verifyToken(tokenResponse.accessToken)

                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@AuthCallbackActivity, "¡Bienvenido ${claims.preferredUsername}!", Toast.LENGTH_SHORT).show()
                        // Navegar a la pantalla principal
                    }
                } catch (e: Exception) {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@AuthCallbackActivity, "Fallo al canjear token: ${e.message}", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }
}
```

---

## 3. Almacenamiento Seguro con `EncryptedSharedPreferences`

Podés crear un adaptador para que los tokens persistan de forma cifrada con el chip de seguridad del dispositivo (Android Keystore):

```kotlin
import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import io.peakauth.TokenStorage

class AndroidSecureTokenStorage(context: Context) : TokenStorage {
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "peak_auth_secure_tokens",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    override fun saveTokens(accessToken: String, refreshToken: String?) {
        prefs.edit().apply {
            putString("access_token", accessToken)
            if (refreshToken != null) {
                putString("refresh_token", refreshToken)
            }
            apply()
        }
    }

    override fun getAccessToken(): String? = prefs.getString("access_token", null)
    override fun getRefreshToken(): String? = prefs.getString("refresh_token", null)

    override fun clear() {
        prefs.edit().clear().apply()
    }
}

// Inicializar el cliente pasándole el storage seguro:
val authClient = PeakAuthClient(
    config = config,
    tokenStorage = AndroidSecureTokenStorage(context)
)
```

---

## 4. Renovación Automática de Token

Cuando el Access Token esté por expirar, podés renovarlo en segundo plano sin interrumpir al usuario:

```kotlin
lifecycleScope.launch(Dispatchers.IO) {
    try {
        val newToken = authClient.refreshToken()
        println("Token renovado con éxito: ${newToken.accessToken}")
    } catch (e: Exception) {
        // El refresh token expiró o fue revocado -> Redirigir a login
        authClient.logout()
    }
}
```

---

## 5. Cierre de Sesión (Logout)

```kotlin
fun logout(context: Context) {
    // 1. Limpiar tokens locales
    authClient.logout()

    // 2. Abrir logout centralizado para destruir la sesión SSO en Peak Auth
    val logoutUrl = authClient.getLogoutUrl(
        postLogoutRedirectUri = "miapp://logged-out"
    )
    val customTabsIntent = CustomTabsIntent.Builder().build()
    customTabsIntent.launchUrl(context, Uri.parse(logoutUrl))
}
```

---

## Licencia

MIT © Bruno Tarditi
