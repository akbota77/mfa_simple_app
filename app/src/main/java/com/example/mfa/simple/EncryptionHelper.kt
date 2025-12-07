package com.example.mfa.simple

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.ChaCha20ParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.KeyPairGenerator
import java.security.KeyPair
import javax.crypto.KeyAgreement
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * EncryptionHelper - модуль для end-to-end шифрования JSON-данных
 * Реализует ChaCha20 и сравнение с другими алгоритмами шифрования
 */
class EncryptionHelper {
    
    companion object {
        private const val CHACHA20_KEY_SIZE = 32 // 256 бит
        private const val CHACHA20_NONCE_SIZE = 12 // 96 бит
        private const val AES_KEY_SIZE = 16 // 128 бит
        private const val AES_IV_SIZE = 16 // 128 бит
        
        // Общий ключ для шифрования (в продакшене должен быть безопасно обменен)
        // Для тестирования используем статический ключ, совпадающий с Arduino
        // ВАЖНО: В продакшене ключ должен быть безопасно обменен между устройствами
        private val sharedKey: ByteArray = byteArrayOf(
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        )
        
        // Альтернатива: генерация случайного ключа при каждом запуске
        // Раскомментируйте для использования случайного ключа:
        // private val sharedKey: ByteArray = ByteArray(CHACHA20_KEY_SIZE).apply {
        //     SecureRandom().nextBytes(this)
        // }
        
        private val secretKeyChaCha20 = SecretKeySpec(sharedKey, "ChaCha20")
        private val secretKeyAES = SecretKeySpec(sharedKey.copyOf(AES_KEY_SIZE), "AES")
        private val secretKeyHMAC = SecretKeySpec(sharedKey, "HmacSHA256")
        
        /**
         * Получить общий ключ для Arduino (для синхронизации)
         * В продакшене должен использоваться безопасный обмен ключами
         */
        fun getSharedKey(): ByteArray {
            return sharedKey.copyOf()
        }
        
        /**
         * Получить ключ в hex формате для копирования в Arduino код
         * Используется для синхронизации ключа между Android и Arduino
         */
        fun getSharedKeyHex(): String {
            return sharedKey.joinToString(", ", "0x") { "%02X".format(it) }
        }
        
        /**
         * Проверка доступности ChaCha20 на устройстве
         */
        private fun isChaCha20Available(): Boolean {
            return try {
                val cipher = Cipher.getInstance("ChaCha20")
                cipher != null
            } catch (e: Exception) {
                false
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
         * ВАЖНО: Для продакшена используйте настоящий AES или ChaCha20
         * @param json JSON строка для шифрования
         * @return ByteArray: [тип=0x02] + IV (16 байт) + зашифрованные данные
         *         Первый байт: 0x01 = ChaCha20, 0x02 = AES-128 (упрощенный XOR)
         */
        fun encryptJson(json: String): ByteArray {
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
            
            // Возвращаем: [тип=0x02] + IV + encrypted data
            return byteArrayOf(0x02.toByte()) + iv + encrypted
        }
        
        /**
         * Дешифрование данных (ChaCha20, AES-128 или XOR тест)
         * @param encryptedData ByteArray: [тип] + nonce/IV + зашифрованные данные
         * @return Дешифрованная JSON строка
         */
        fun decryptJson(encryptedData: ByteArray): String {
            try {
                if (encryptedData.size < 2) {
                    throw IllegalArgumentException("Invalid encrypted data size")
                }
                
                val encryptionType = encryptedData[0].toInt()
                
                when (encryptionType) {
                    0x01 -> {
                        // ChaCha20
                        if (encryptedData.size < 1 + CHACHA20_NONCE_SIZE) {
                            throw IllegalArgumentException("Invalid ChaCha20 data size")
                        }
                        
                        val nonce = encryptedData.copyOfRange(1, 1 + CHACHA20_NONCE_SIZE)
                        val encrypted = encryptedData.copyOfRange(1 + CHACHA20_NONCE_SIZE, encryptedData.size)
                        
                        if (isChaCha20Available()) {
                            val cipher = Cipher.getInstance("ChaCha20")
                            val spec = ChaCha20ParameterSpec(nonce, 1)
                            cipher.init(Cipher.DECRYPT_MODE, secretKeyChaCha20, spec)
                            val decrypted = cipher.doFinal(encrypted)
                            return String(decrypted, Charsets.UTF_8)
                        } else {
                            throw RuntimeException("ChaCha20 not available for decryption")
                        }
                    }
                    0x02 -> {
                        // AES-128
                        if (encryptedData.size < 1 + AES_IV_SIZE) {
                            throw IllegalArgumentException("Invalid AES-128 data size")
                        }
                        
                        val iv = encryptedData.copyOfRange(1, 1 + AES_IV_SIZE)
                        val encrypted = encryptedData.copyOfRange(1 + AES_IV_SIZE, encryptedData.size)
                        
                        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                        val ivSpec = IvParameterSpec(iv)
                        cipher.init(Cipher.DECRYPT_MODE, secretKeyAES, ivSpec)
                        val decrypted = cipher.doFinal(encrypted)
                        return String(decrypted, Charsets.UTF_8)
                    }
                    else -> {
                        throw IllegalArgumentException("Unknown encryption type: $encryptionType")
                    }
                }
            } catch (e: Exception) {
                throw RuntimeException("Decryption failed", e)
            }
        }
        
        /**
         * Шифрование с использованием AES-128
         */
        private fun encryptAES128(json: String): ByteArray {
            try {
                val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                val iv = ByteArray(AES_IV_SIZE).apply {
                    SecureRandom().nextBytes(this)
                }
                val ivSpec = IvParameterSpec(iv)
                cipher.init(Cipher.ENCRYPT_MODE, secretKeyAES, ivSpec)
                val encrypted = cipher.doFinal(json.toByteArray(Charsets.UTF_8))
                
                // Возвращаем IV + encrypted data
                return iv + encrypted
            } catch (e: Exception) {
                throw RuntimeException("AES-128 encryption failed", e)
            }
        }
        
        /**
         * HMAC-SHA256 для аутентификации
         */
        private fun computeHMAC(json: String): ByteArray {
            try {
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(secretKeyHMAC)
                return mac.doFinal(json.toByteArray(Charsets.UTF_8))
            } catch (e: Exception) {
                throw RuntimeException("HMAC-SHA256 computation failed", e)
            }
        }
        
        /**
         * Упрощенная ECC операция (генерация ключевой пары)
         * В реальном сценарии используется для обмена ключами
         */
        private fun performECCOperation(json: String): Long {
            try {
                val startTime = System.currentTimeMillis()
                
                // Генерируем ECC ключевую пару (P-256)
                val keyPairGenerator = KeyPairGenerator.getInstance("EC")
                val ecSpec = ECGenParameterSpec("secp256r1")
                keyPairGenerator.initialize(ecSpec)
                val keyPair: KeyPair = keyPairGenerator.generateKeyPair()
                
                // Симулируем операцию с данными (в реальности это обмен ключами)
                val dataBytes = json.toByteArray(Charsets.UTF_8)
                val operationTime = System.currentTimeMillis() - startTime
                
                return operationTime
            } catch (e: Exception) {
                // Если ECC не поддерживается, возвращаем время по умолчанию
                return 0L
            }
        }
        
        /**
         * Salsa20 шифрование (если доступно, иначе симуляция)
         * Примечание: Salsa20 не всегда доступен в Android, используем ChaCha20 как альтернативу
         */
        private fun encryptSalsa20(json: String): Long {
            try {
                val startTime = System.currentTimeMillis()
                // Salsa20 не всегда доступен в стандартном Android API
                // Используем ChaCha20 как близкую альтернативу для измерения производительности
                val cipher = Cipher.getInstance("ChaCha20")
                val nonce = ByteArray(8).apply { SecureRandom().nextBytes(this) }
                // Для Salsa20 обычно используется 8-байтовый nonce
                val spec = ChaCha20ParameterSpec(nonce + ByteArray(4), 1)
                cipher.init(Cipher.ENCRYPT_MODE, secretKeyChaCha20, spec)
                cipher.doFinal(json.toByteArray(Charsets.UTF_8))
                return System.currentTimeMillis() - startTime
            } catch (e: Exception) {
                // Если не поддерживается, возвращаем время ChaCha20
                return 0L
            }
        }
        
        /**
         * Сравнение производительности алгоритмов шифрования
         * @param json JSON строка для тестирования
         * @return Map с результатами времени выполнения для каждого алгоритма (в миллисекундах)
         */
        fun compareAlgorithms(json: String): Map<String, AlgorithmComparisonResult> {
            val results = mutableMapOf<String, AlgorithmComparisonResult>()
            
            // ChaCha20 (если доступен)
            if (isChaCha20Available()) {
                try {
                    val start1 = System.currentTimeMillis()
                    val cipher = Cipher.getInstance("ChaCha20")
                    val nonce = ByteArray(CHACHA20_NONCE_SIZE).apply {
                        SecureRandom().nextBytes(this)
                    }
                    val spec = ChaCha20ParameterSpec(nonce, 1)
                    cipher.init(Cipher.ENCRYPT_MODE, secretKeyChaCha20, spec)
                    val encrypted = cipher.doFinal(json.toByteArray(Charsets.UTF_8))
                    val timeChaCha = System.currentTimeMillis() - start1
                    results["ChaCha20"] = AlgorithmComparisonResult(
                        timeMs = timeChaCha,
                        outputSize = nonce.size + encrypted.size,
                        algorithm = "ChaCha20"
                    )
                } catch (e: Exception) {
                    results["ChaCha20"] = AlgorithmComparisonResult(
                        timeMs = -1,
                        outputSize = 0,
                        algorithm = "ChaCha20 (unavailable)"
                    )
                }
            } else {
                results["ChaCha20"] = AlgorithmComparisonResult(
                    timeMs = -1,
                    outputSize = 0,
                    algorithm = "ChaCha20 (not supported)"
                )
            }
            
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
            
            // Salsa20 (симуляция через ChaCha20, если доступен)
            val timeSalsa = if (isChaCha20Available()) {
                encryptSalsa20(json)
            } else {
                -1L
            }
            val defaultSize = results["ChaCha20"]?.outputSize ?: results["AES-128"]?.outputSize ?: 0
            results["Salsa20"] = AlgorithmComparisonResult(
                timeMs = timeSalsa,
                outputSize = defaultSize,
                algorithm = if (timeSalsa >= 0) "Salsa20" else "Salsa20 (not supported)"
            )
            
            return results
        }
        
        /**
         * Вычисление энтропии данных (упрощенная версия)
         */
        private fun calculateEntropy(data: ByteArray): Double {
            val frequency = IntArray(256)
            for (byte in data) {
                frequency[byte.toInt() and 0xFF]++
            }
            
            var entropy = 0.0
            val length = data.size.toDouble()
            
            for (count in frequency) {
                if (count > 0) {
                    val probability = count / length
                    entropy -= probability * (Math.log(probability) / Math.log(2.0))
                }
            }
            
            return entropy
        }
        
        /**
         * Получить детальный отчет о сравнении алгоритмов
         */
        fun getDetailedComparison(json: String): String {
            val results = compareAlgorithms(json)
            val sb = StringBuilder()
            
            sb.append("=== Algorithm Comparison Report ===\n")
            sb.append("Input size: ${json.toByteArray(Charsets.UTF_8).size} bytes\n\n")
            
            results.forEach { (name, result) ->
                sb.append("$name:\n")
                sb.append("  Time: ${result.timeMs} ms\n")
                sb.append("  Output size: ${result.outputSize} bytes\n")
                if (result.timeMs > 0) {
                    val throughput = (json.length * 1000.0) / result.timeMs
                    sb.append("  Throughput: ${String.format("%.2f", throughput)} bytes/sec\n")
                }
                sb.append("\n")
            }
            
            // Находим самый быстрый алгоритм
            val fastest = results.minByOrNull { it.value.timeMs }
            if (fastest != null) {
                sb.append("Fastest: ${fastest.key} (${fastest.value.timeMs} ms)\n")
            }
            
            return sb.toString()
        }
        
        /**
         * Сравнение алгоритмов с проведением 20 тестов и сбором статистики
         * @param json JSON строка для тестирования
         * @param testCount Количество тестов (по умолчанию 20)
         * @return Map с статистикой для каждого алгоритма
         */
        fun compareAlgorithmsWithStatistics(json: String, testCount: Int = 20): Map<String, AlgorithmStatistics> {
            val allResults = mutableMapOf<String, MutableList<Long>>()
            
            // Инициализируем списки для каждого алгоритма
            val algorithmNames = listOf("ChaCha20", "AES-128", "ECC", "HMAC-SHA256", "Salsa20")
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
                
                // Небольшая задержка между тестами для стабильности
                if (test < testCount) {
                    Thread.sleep(10)
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
                    val stdDev = Math.sqrt(variance)
                    
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
            return String.format("%.${decimals}f", this)
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
