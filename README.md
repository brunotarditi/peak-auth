# 🏔️ Peak Auth - Sistema de Autenticación SSO

![Go Version](https://img.shields.io/badge/go-1.24.0-blue.svg)
![Gin Framework](https://img.shields.io/badge/gin-v1.11.0-blue.svg)
![PostgreSQL](https://img.shields.io/badge/postgresql-v1.6.0-blue.svg)

**Peak Auth** es un proveedor de identidad y autenticación (SSO) que permite que múltiples aplicaciones se autentiquen de forma centralizada mediante **JWT asimétrico (RSA-256)**. El sistema maneja roles, contraseñas robustas y reglas de autorización para controlar el acceso a través de diferentes aplicaciones.

---

## ✨ Características Principales

- 🔐 **Autenticación centralizada** mediante JWT asimétrico (RSA-256)
- 👥 **Gestión de roles y permisos** por aplicación
- 🛡️ **Contraseñas robustas** con hash criptográfico (bcrypt)
- ⚙️ **Reglas de autorización** configurables por aplicación
- 🖥️ **Interfaz administrativa** con HTML + Tailwind CSS
- 🏢 **Sistema multi-tenancy** (múltiples aplicaciones pueden usar el SSO)
- 📧 **Verificación de email** y recuperación de contraseña (Resend)
- 🔄 **Refresh tokens** para renovación segura de sesiones

## 🛠️ Stack Tecnológico

- **Lenguaje**: Go (1.24.0)
- **Web Framework**: Gin
- **ORM**: GORM
- **Base de Datos**: PostgreSQL
- **Seguridad**: JWT (golang-jwt), RSA-256, bcrypt
- **Frontend**: HTML + Tailwind CSS
- **Email**: Resend

## 🚀 Instalación y Desarrollo Local

### Requisitos Previos

- Go 1.24.0+
- PostgreSQL 13+
- OpenSSL (para generar claves RSA)

### Pasos de instalación

1. **Clonar el repositorio:**

   ```bash
   git clone https://github.com/brunotarditi/peak-auth.git
   cd peak-auth
   ```

2. **Instalar dependencias:**

   ```bash
   go mod download
   ```

3. **Configurar variables de entorno:**
   Copia el archivo de ejemplo y configura tus datos (base de datos, puerto, etc.).

   ```bash
   cp .env.example .env
   ```

4. **Generar claves RSA para JWT:**

   ```bash
   openssl genpkey -algorithm RSA -out jwt_private.pem -pkeyopt rsa_keygen_bits:2048
   openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem
   ```

5. **Ejecutar el servidor:**
   ```bash
   go run main.go
   ```

## 🐳 Docker

También puedes ejecutar Peak Auth usando Docker:

```bash
docker build -t peak-auth .
docker run -p 8080:8080 \
  -e DATABASE_URL=postgres://... \
  -e JWT_PRIVATE_KEY_PATH=/keys/jwt_private.pem \
  -v /path/to/keys:/keys \
  peak-auth
```

## 🔌 Cómo integrar tu aplicación

Peak Auth utiliza un sistema de **JWT Asimétrico**. Peak Auth firma el token JWT con su **clave privada**, y de esta manera tu aplicación solo necesita la **clave pública** para verificar la autenticidad del token, sin tener que comunicarse de vuelta con Peak Auth.

Ejemplo básico de integración en Node.js/Express:

```javascript
const jwt = require("jsonwebtoken");
const fs = require("fs");

// Descargar/obtener la clave pública de Peak Auth
const publicKeyPEM = fs.readFileSync("./jwt_public.pem", "utf-8");

app.get("/api/protected", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const decoded = jwt.verify(token, publicKeyPEM, { algorithms: ["RS256"] });
    res.json({ message: "Acceso permitido", user: decoded });
  } catch (err) {
    res.status(403).json({ error: "Token inválido" });
  }
});
```

## 🤝 Contribuir

1. Haz un fork del proyecto
2. Crea tu rama de características (`git checkout -b feature/nueva-funcionalidad`)
3. Haz commit de tus cambios (`git commit -m 'Añadir nueva funcionalidad'`)
4. Haz push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request

## 📄 Licencia

Este proyecto está bajo la Licencia MIT - mira el archivo [LICENSE](LICENSE) para más detalles.
