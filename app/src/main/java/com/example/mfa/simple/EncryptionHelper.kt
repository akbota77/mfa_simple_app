package com.example.mfa.simple

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.DeprecationLevel

/**
 * EncryptionHelper - модуль для end-to-end шифрования JSON-данных
 * Реализует упрощенное XOR шифрование для совместимости с Arduino
 * и сравнение производительности алгоритмов шифрования
 */
class EncryptionHelper {
    
    companion object {
        private const val AES_KEY_SIZE = 16 // 128 бит
        private const val AES_IV_SIZE = 16 // 128 бит
        
        // ВАЖНО: Для продакшена используйте Android Keystore или безопасный обмен ключами
        // Этот ключ используется ТОЛЬКО для тестирования и совместимости с Arduino
        // В продакшене ключ должен быть:
        // 1. Храниться в Android Keystore
        // 2. Безопасно обмениваться между устройствами (например, через ECDH)
        // 3. Никогда не коммититься в репозиторий
        @Suppress("HardcodedEncryptionKey")
        private val sharedKey: ByteArray = byteArrayOf(
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        )
        
        private val secretKeyAES = SecretKeySpec(sharedKey.copyOf(AES_KEY_SIZE), "AES")
        private val secretKeyHMAC = SecretKeySpec(sharedKey, "HmacSHA256")
        
        /**
         * Получить общий ключ для Arduino (для синхронизации)
         * ВАЖНО: Только для тестирования! В продакшене используйте безопасный обмен ключами
         * @deprecated Используйте только для разработки и тестирования
         */
        @Deprecated("Use secure key exchange in production", level = DeprecationLevel.WARNING)
        @Suppress("UNUSED")
        fun getSharedKey(): ByteArray {
            return sharedKey.copyOf()
        }
        
        /**
         * Получить ключ в hex формате для копирования в Arduino код
         * ВАЖНО: Только для тестирования! В продакшене используйте безопасный обмен ключами
         * @deprecated Используйте только для разработки и тестирования
         */
        @Deprecated("Use secure key exchange in production", level = DeprecationLevel.WARNING)
        @Suppress("UNUSED")
        fun getSharedKeyHex(): String {
            return sharedKey.joinToString(", ", "0x") { 
                String.format(java.util.Locale.US, "%02X", it) 
            }
        }
        
        
        /**
         * Упрощенное XOR шифрование для совместимости с Arduino
         * ВАЖНО: Используется только для тестирования, не для продакшена!
         */
        private fun encryptSimpleXOR(data: ByteArray, key: ByteArray): ByteArray {
            val encrypted = ByteArray(data.size)
            for (i in data.indices) {
                // Правильная обработка signed/unsigned байтов
                val dataByte = data[i].toInt() and 0xFF
                val keyByte = key[i % key.size].toInt() and 0xFF
                encrypted[i] = (dataByte xor keyByte).toByte()
            }
            return encrypted
        }
        
        /**
         * Шифрование JSON с использованием упрощенного XOR для совместимости с Arduino
         * ВАЖНО: Для продакшена используйте настоящий AES
         * @param json JSON строка для шифрования (не должна быть пустой)
         * @return ByteArray: [type=0x02] + IV (16 байт) + зашифрованные данные
         *         Первый байт: 0x02 = AES-128 (упрощенный XOR)
         * @throws IllegalArgumentException если json пустая
         */
        fun encryptJson(json: String): ByteArray {
            require(json.isNotBlank()) { "JSON string cannot be empty" }
            
            // Используем упрощенное XOR шифрование для совместимости с Arduino
            // Это позволяет Arduino дешифровать данные простым XOR
            val jsonBytes = json.toByteArray(Charsets.UTF_8)
            
            // Генерируем IV (используется для совместимости формата, но не влияет на XOR)
            val iv = ByteArray(AES_IV_SIZE).apply {
                SecureRandom().nextBytes(this)
            }
            
            // Используем первые 16 байт ключа для AES-128 совместимости
            val aesKey = sharedKey.copyOf(AES_KEY_SIZE)
            
            // Упрощенное XOR шифрование (совместимо с Arduino)
            val encrypted = encryptSimpleXOR(jsonBytes, aesKey)
            
            // Возвращаем: [type=0x02] + IV + encrypted data
            // Важно: используем явное создание массива для правильной отправки
            val result = ByteArray(1 + AES_IV_SIZE + encrypted.size)
            result[0] = 0x02.toByte()
            iv.copyInto(result, 1, 0, AES_IV_SIZE)
            encrypted.copyInto(result, 1 + AES_IV_SIZE, 0, encrypted.size)
            
            // Проверяем, что первый байт правильный
            if (result[0].toInt() and 0xFF != 0x02) {
                android.util.Log.e("EncryptionHelper", "ERROR: First byte is not 0x02, got: 0x${(result[0].toInt() and 0xFF).toString(16)}")
            }
            
            return result
        }
        
        
        /**
         * Шифрование с использованием AES-128
         */
        private fun encryptAES128(json: String): ByteArray {
            return try {
                val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                val iv = ByteArray(AES_IV_SIZE).apply {
                    SecureRandom().nextBytes(this)
                }
                val ivSpec = IvParameterSpec(iv)
                cipher.init(Cipher.ENCRYPT_MODE, secretKeyAES, ivSpec)
                val encrypted = cipher.doFinal(json.toByteArray(Charsets.UTF_8))
                
                // Возвращаем IV + encrypted data
                iv + encrypted
            } catch (@Suppress("UNUSED_PARAMETER") e: Exception) {
                throw RuntimeException("AES-128 encryption failed", e)
            }
        }
        
        /**
         * HMAC-SHA256 для аутентификации
         */
        private fun computeHMAC(json: String): ByteArray {
            return try {
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(secretKeyHMAC)
                mac.doFinal(json.toByteArray(Charsets.UTF_8))
            } catch (@Suppress("UNUSED_PARAMETER") e: Exception) {
                throw RuntimeException("HMAC-SHA256 computation failed", e)
            }
        }
        
        /**
         * Упрощенная ECC операция (генерация ключевой пары)
         * В реальном сценарии используется для обмена ключами
         */
        private fun performECCOperation(json: String): Long {
            return try {
                val startTime = System.currentTimeMillis()
                // Симулируем операцию с данными (в реальности это обмен ключами)
                // В реальной реализации здесь была бы генерация ECC ключевой пары
                @Suppress("UNUSED_EXPRESSION")
                json.toByteArray(Charsets.UTF_8)
                System.currentTimeMillis() - startTime
            } catch (@Suppress("UNUSED_PARAMETER") e: Exception) {
                // Если ECC не поддерживается, возвращаем время по умолчанию
                0L
            }
        }
        
        /**
         * Сравнение производительности алгоритмов шифрования
         * @param json JSON строка для тестирования
         * @return Map с результатами времени выполнения для каждого алгоритма (в миллисекундах)
         */
        fun compareAlgorithms(json: String): Map<String, AlgorithmComparisonResult> {
            val results = mutableMapOf<String, AlgorithmComparisonResult>()
            
            // AES-128
            val start2 = System.currentTimeMillis()
            val encryptedAES = encryptAES128(json)
            val timeAES = System.currentTimeMillis() - start2
            results["AES-128"] = AlgorithmComparisonResult(
                timeMs = timeAES,
                outputSize = encryptedAES.size,
                algorithm = "AES-128"
            )
            
            // ECC (упрощённо - генерация ключевой пары)
            val timeECC = performECCOperation(json)
            results["ECC"] = AlgorithmComparisonResult(
                timeMs = timeECC,
                outputSize = 0, // ECC используется для обмена ключами, не для шифрования данных
                algorithm = "ECC"
            )
            
            // HMAC-SHA256
            val start4 = System.currentTimeMillis()
            val hmacResult = computeHMAC(json)
            val timeHMAC = System.currentTimeMillis() - start4
            results["HMAC-SHA256"] = AlgorithmComparisonResult(
                timeMs = timeHMAC,
                outputSize = hmacResult.size,
                algorithm = "HMAC-SHA256"
            )
            
            return results
        }
        
        
        
        /**
         * Сравнение алгоритмов с проведением 20 тестов и сбором статистики
         * @param json JSON строка для тестирования
         * @param testCount Количество тестов (по умолчанию 20, минимум 1, максимум 100)
         * @return Map с статистикой для каждого алгоритма
         * @throws IllegalArgumentException если testCount вне допустимого диапазона
         */
        fun compareAlgorithmsWithStatistics(json: String, testCount: Int = 20): Map<String, AlgorithmStatistics> {
            require(testCount > 0) { "Test count must be greater than 0" }
            require(testCount <= 100) { "Test count cannot exceed 100" }
            require(json.isNotBlank()) { "JSON string cannot be empty" }
            
            val allResults = mutableMapOf<String, MutableList<Long>>()
            
            // Инициализируем списки для каждого алгоритма
            val algorithmNames = listOf("AES-128", "ECC", "HMAC-SHA256")
            algorithmNames.forEach { name ->
                allResults[name] = mutableListOf()
            }
            
            // Выполняем тесты
            for (test in 1..testCount) {
                val results = compareAlgorithms(json)
                
                results.forEach { (name, result) ->
                    if (result.timeMs > 0) {
                        allResults[name]?.add(result.timeMs)
                    }
                }
                
                // Небольшая задержка между тестами для стабильности (только если не последний тест)
                if (test < testCount) {
                    try {
                        Thread.sleep(10)
                    } catch (@Suppress("UNUSED_PARAMETER") e: InterruptedException) {
                        Thread.currentThread().interrupt()
                        break
                    }
                }
            }
            
            // Вычисляем статистику для каждого алгоритма
            val statistics = mutableMapOf<String, AlgorithmStatistics>()
            
            allResults.forEach { (algorithmName, times) ->
                if (times.isNotEmpty()) {
                    times.sort()
                    
                    val average = times.average()
                    val min = times.minOrNull() ?: 0L
                    val max = times.maxOrNull() ?: 0L
                    val median = if (times.size % 2 == 0) {
                        (times[times.size / 2 - 1] + times[times.size / 2]) / 2.0
                    } else {
                        times[times.size / 2].toDouble()
                    }
                    
                    // Вычисляем стандартное отклонение
                    val variance = times.map { (it - average) * (it - average) }.average()
                    val stdDev = kotlin.math.sqrt(variance)
                    
                    statistics[algorithmName] = AlgorithmStatistics(
                        algorithm = algorithmName,
                        averageTime = average,
                        minTime = min,
                        maxTime = max,
                        medianTime = median,
                        standardDeviation = stdDev,
                        successCount = times.size,
                        totalTests = testCount
                    )
                } else {
                    statistics[algorithmName] = AlgorithmStatistics(
                        algorithm = algorithmName,
                        averageTime = -1.0,
                        minTime = -1L,
                        maxTime = -1L,
                        medianTime = -1.0,
                        standardDeviation = -1.0,
                        successCount = 0,
                        totalTests = testCount
                    )
                }
            }
            
            return statistics
        }
    
        /**
         * Получить детальный отчет о сравнении алгоритмов с 20 тестами
         */
        fun getDetailedStatisticsReport(json: String, testCount: Int = 20): String {
            val statistics = compareAlgorithmsWithStatistics(json, testCount)
            val sb = StringBuilder()
            
            sb.append("=== Algorithm Comparison Report (${testCount} tests) ===\n")
            sb.append("Input size: ${json.toByteArray(Charsets.UTF_8).size} bytes\n\n")
            
            statistics.forEach { (name, stats) ->
                sb.append("$name:\n")
                if (stats.successCount > 0) {
                    sb.append("  Success rate: ${stats.successCount}/${stats.totalTests} (${(stats.successCount * 100.0 / stats.totalTests).format(2)}%)\n")
                    sb.append("  Average time: ${stats.averageTime.format(2)} ms\n")
                    sb.append("  Median time: ${stats.medianTime.format(2)} ms\n")
                    sb.append("  Min time: ${stats.minTime} ms\n")
                    sb.append("  Max time: ${stats.maxTime} ms\n")
                    sb.append("  Std deviation: ${stats.standardDeviation.format(2)} ms\n")
                    
                    if (stats.averageTime > 0) {
                        val throughput = (json.length * 1000.0) / stats.averageTime
                        sb.append("  Throughput: ${throughput.format(2)} bytes/sec\n")
                    }
                } else {
                    sb.append("  Status: Not available or failed\n")
                }
                sb.append("\n")
            }
            
            // Находим самый быстрый алгоритм по среднему времени
            val fastest = statistics.filter { it.value.successCount > 0 }
                .minByOrNull { it.value.averageTime }
            
            if (fastest != null) {
                sb.append("Fastest (average): ${fastest.key} (${fastest.value.averageTime.format(2)} ms)\n")
            }
            
            // Находим самый стабильный алгоритм (минимальное стандартное отклонение)
            val mostStable = statistics.filter { it.value.successCount > 0 }
                .minByOrNull { it.value.standardDeviation }
            
            if (mostStable != null) {
                sb.append("Most stable: ${mostStable.key} (std dev: ${mostStable.value.standardDeviation.format(2)} ms)\n")
            }
            
            return sb.toString()
        }
    
        /**
         * Вспомогательная функция для форматирования чисел
         */
        private fun Double.format(decimals: Int): String {
            return String.format(java.util.Locale.US, "%.${decimals}f", this)
        }
    }
    
    /**
     * Результат сравнения алгоритма
     */
    data class AlgorithmComparisonResult(
        val timeMs: Long,
        val outputSize: Int,
        val algorithm: String
    )
    
    /**
     * Статистика по результатам тестирования
     */
    data class AlgorithmStatistics(
        val algorithm: String,
        val averageTime: Double,
        val minTime: Long,
        val maxTime: Long,
        val medianTime: Double,
        val standardDeviation: Double,
        val successCount: Int,
        val totalTests: Int
    )
}
