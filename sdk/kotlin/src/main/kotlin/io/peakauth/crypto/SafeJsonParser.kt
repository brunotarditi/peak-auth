package io.peakauth.crypto

import java.math.BigInteger

/**
 * Parser JSON tipado y seguro de cero dependencias externas para Peak Auth SDK.
 * Reemplaza parsers basados en expresiones regulares por un analizador sintáctico recursivo robusto.
 */
object SafeJsonParser {

    /**
     * Parsea un texto JSON que representa un objeto `{ ... }` y retorna un [Map].
     */
    fun parseObject(json: String): Map<String, Any?> {
        val parser = StringParser(json)
        val value = parser.parseValue()
        parser.skipWhitespace()
        if (parser.hasMore()) {
            throw IllegalArgumentException("PeakAuth JSON: contenido inesperado tras el fin del objeto JSON")
        }
        if (value !is Map<*, *>) {
            throw IllegalArgumentException("PeakAuth JSON: se esperaba un objeto JSON en la raíz")
        }
        @Suppress("UNCHECKED_CAST")
        return value as Map<String, Any?>
    }

    /**
     * Parsea un texto JSON arbitrario (objeto o array).
     */
    fun parse(json: String): Any? {
        val parser = StringParser(json)
        val value = parser.parseValue()
        parser.skipWhitespace()
        if (parser.hasMore()) {
            throw IllegalArgumentException("PeakAuth JSON: contenido inesperado tras el fin de JSON")
        }
        return value
    }

    fun getString(map: Map<String, Any?>, key: String): String? {
        val v = map[key] ?: return null
        return v as? String
    }

    fun getLong(map: Map<String, Any?>, key: String): Long? {
        val v = map[key] ?: return null
        return when (v) {
            is Number -> v.toLong()
            is String -> v.toLongOrNull()
            else -> null
        }
    }

    fun getBoolean(map: Map<String, Any?>, key: String): Boolean? {
        val v = map[key] ?: return null
        return when (v) {
            is Boolean -> v
            is String -> v.toBooleanStrictOrNull()
            else -> null
        }
    }

    fun getStringList(map: Map<String, Any?>, key: String): List<String> {
        val v = map[key] ?: return emptyList()
        return when (v) {
            is List<*> -> v.filterIsInstance<String>()
            is String -> listOf(v)
            else -> emptyList()
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun getObjectList(map: Map<String, Any?>, key: String): List<Map<String, Any?>> {
        val v = map[key] ?: return emptyList()
        if (v !is List<*>) return emptyList()
        return v.filterIsInstance<Map<String, Any?>>()
    }

    @Suppress("UNCHECKED_CAST")
    fun getObject(map: Map<String, Any?>, key: String): Map<String, Any?>? {
        val v = map[key] ?: return null
        return v as? Map<String, Any?>
    }

    private class StringParser(private val src: String) {
        private var pos = 0

        fun hasMore(): Boolean = pos < src.length

        fun peek(): Char = if (hasMore()) src[pos] else '\u0000'

        fun next(): Char = if (hasMore()) src[pos++] else '\u0000'

        fun skipWhitespace() {
            while (hasMore()) {
                val c = src[pos]
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++
                } else {
                    break
                }
            }
        }

        fun parseValue(): Any? {
            skipWhitespace()
            if (!hasMore()) throw IllegalArgumentException("PeakAuth JSON: final de entrada inesperado")

            return when (val c = peek()) {
                '{' -> parseObjectInternal()
                '[' -> parseArrayInternal()
                '"' -> parseStringInternal()
                't', 'f' -> parseBooleanInternal()
                'n' -> parseNullInternal()
                '-', in '0'..'9' -> parseNumberInternal()
                else -> throw IllegalArgumentException("PeakAuth JSON: carácter inesperado '$c' en posición $pos")
            }
        }

        private fun parseObjectInternal(): Map<String, Any?> {
            expect('{')
            skipWhitespace()
            val map = mutableMapOf<String, Any?>()

            if (peek() == '}') {
                next()
                return map
            }

            while (true) {
                skipWhitespace()
                val key = parseStringInternal()
                skipWhitespace()
                expect(':')
                val value = parseValue()
                map[key] = value

                skipWhitespace()
                when (val c = next()) {
                    '}' -> return map
                    ',' -> continue
                    else -> throw IllegalArgumentException("PeakAuth JSON: se esperaba ',' o '}' pero se encontró '$c' en pos $pos")
                }
            }
        }

        private fun parseArrayInternal(): List<Any?> {
            expect('[')
            skipWhitespace()
            val list = mutableListOf<Any?>()

            if (peek() == ']') {
                next()
                return list
            }

            while (true) {
                val item = parseValue()
                list.add(item)
                skipWhitespace()
                when (val c = next()) {
                    ']' -> return list
                    ',' -> continue
                    else -> throw IllegalArgumentException("PeakAuth JSON: se esperaba ',' o ']' pero se encontró '$c' en pos $pos")
                }
            }
        }

        private fun parseStringInternal(): String {
            expect('"')
            val sb = StringBuilder()
            while (hasMore()) {
                val c = next()
                if (c < ' ') {
                    throw IllegalArgumentException("PeakAuth JSON: carácter de control no escapado (código ${c.code}) dentro de cadena")
                }
                when (c) {
                    '"' -> return sb.toString()
                    '\\' -> {
                        if (!hasMore()) throw IllegalArgumentException("PeakAuth JSON: escape inconcluso al final")
                        when (val esc = next()) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                if (pos + 4 > src.length) throw IllegalArgumentException("PeakAuth JSON: secuencia unicode incompleta en pos $pos")
                                val hex = src.substring(pos, pos + 4)
                                for (h in hex) {
                                    if (h !in '0'..'9' && h !in 'a'..'f' && h !in 'A'..'F') {
                                        throw IllegalArgumentException("PeakAuth JSON: dígito hexadecimal no válido '$h' en secuencia \\u$hex")
                                    }
                                }
                                pos += 4
                                val code = hex.toInt(16)
                                sb.append(code.toChar())
                            }
                            else -> throw IllegalArgumentException("PeakAuth JSON: secuencia de escape no válida '\\$esc'")
                        }
                    }
                    else -> sb.append(c)
                }
            }
            throw IllegalArgumentException("PeakAuth JSON: cadena no terminada con comillas")
        }

        private fun parseBooleanInternal(): Boolean {
            if (src.startsWith("true", pos)) {
                pos += 4
                return true
            }
            if (src.startsWith("false", pos)) {
                pos += 5
                return false
            }
            throw IllegalArgumentException("PeakAuth JSON: valor booleano inválido en pos $pos")
        }

        private fun parseNullInternal(): Any? {
            if (src.startsWith("null", pos)) {
                pos += 4
                return null
            }
            throw IllegalArgumentException("PeakAuth JSON: valor null inválido en pos $pos")
        }

        private fun parseNumberInternal(): Number {
            val start = pos
            if (peek() == '-') next()
            if (!hasMore()) {
                throw IllegalArgumentException("PeakAuth JSON: número malformado '-' sin dígitos")
            }

            val firstDigit = peek()
            if (firstDigit !in '0'..'9') {
                throw IllegalArgumentException("PeakAuth JSON: número malformado con carácter inesperado '$firstDigit'")
            }
            if (firstDigit == '0') {
                next()
                if (hasMore() && peek() in '0'..'9') {
                    throw IllegalArgumentException("PeakAuth JSON: los números no pueden tener ceros a la izquierda")
                }
            } else {
                while (hasMore() && peek() in '0'..'9') next()
            }

            var isFloating = false
            if (hasMore() && peek() == '.') {
                isFloating = true
                next()
                if (!hasMore() || peek() !in '0'..'9') {
                    throw IllegalArgumentException("PeakAuth JSON: punto decimal sin dígitos posteriores en posición $pos")
                }
                while (hasMore() && peek() in '0'..'9') next()
            }

            if (hasMore() && (peek() == 'e' || peek() == 'E')) {
                isFloating = true
                next()
                if (hasMore() && (peek() == '+' || peek() == '-')) next()
                if (!hasMore() || peek() !in '0'..'9') {
                    throw IllegalArgumentException("PeakAuth JSON: exponente sin dígitos posteriores en posición $pos")
                }
                while (hasMore() && peek() in '0'..'9') next()
            }

            val numStr = src.substring(start, pos)
            return try {
                if (isFloating) {
                    numStr.toDouble()
                } else {
                    numStr.toLongOrNull() ?: BigInteger(numStr)
                }
            } catch (e: Exception) {
                throw IllegalArgumentException("PeakAuth JSON: número inválido '$numStr': ${e.message}", e)
            }
        }

        private fun expect(expected: Char) {
            val c = next()
            if (c != expected) {
                throw IllegalArgumentException("PeakAuth JSON: se esperaba '$expected' pero se obtuvo '$c' en pos $pos")
            }
        }
    }
}
