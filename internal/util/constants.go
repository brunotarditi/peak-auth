package util

const AppIdPeakAuth = "peak-auth"

// BcryptMaxPasswordBytes es el límite real de bcrypt: ignora todo byte más allá
// del 72. Validar explícitamente evita truncados silenciosos.
const BcryptMaxPasswordBytes = 72
