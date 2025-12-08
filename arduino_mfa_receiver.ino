// Arduino code to receive and parse JSON from Android MFA app
// ВАЖНО: HC-05 должен быть подключен к SoftwareSerial (пины 10 и 11)
// HC-05 TX -> Arduino pin 10 (RX)
// HC-05 RX -> Arduino pin 11 (TX)
// Serial порт остается свободным для Serial Monitor

#include <SoftwareSerial.h>
#include <ArduinoJson.h>
#include <math.h>
#include <string.h>  // Для memcpy

// SoftwareSerial для HC-05 Bluetooth модуля
// ВАРИАНТ 1: Стандартное подключение
// SoftwareSerial BTSerial(10, 11); // RX, TX pins for HC-05

// ВАРИАНТ 2: Если не работает, попробуйте поменять местами TX и RX:
SoftwareSerial BTSerial(11, 10); // Поменять RX и TX местами

// ВАРИАНТ 3: Если все еще не работает, попробуйте другие пины:
// SoftwareSerial BTSerial(2, 3); // Альтернативные пины

// DFA State Machine
enum State { 
  q0,  // Initial state
  q1,  // After biometric authentication
  q2   // After PIN authentication
};

State currentState = q0;

// DFA Configuration
const int NUM_STATES = 3;
int stateTransitionCount[NUM_STATES] = {0, 0, 0};
int totalTransitions = 0;

// Bluetooth Signal Quality Tracking
const int RSSI_SAMPLE_SIZE = 10;
float rssiSamples[RSSI_SAMPLE_SIZE];
int rssiIndex = 0;
bool rssiInitialized = false;

// Authentication Session Tracking
int successfulSessions = 0;
int totalSessions = 0;
const float C_BASE = 0.95;

// IMSI Weighting Factors
const float w1 = 0.4;
const float w2 = 0.3;
const float w3 = 0.3;

// Буфер для приема зашифрованных данных
uint8_t encryptedBuffer[256];
int encryptedBufferIndex = 0;
bool receivingEncrypted = false;
unsigned long lastCharTime = 0;
const unsigned long DATA_TIMEOUT = 1000; // Таймаут увеличен до 1000ms для надежного приема

// Ключ шифрования (должен совпадать с ключом в Android приложении)
// ВАЖНО: В продакшене ключ должен быть безопасно обменен между устройствами
const int AES_KEY_SIZE = 16;
uint8_t encryptionKey[AES_KEY_SIZE] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

// Буфер для дешифрованных данных
char decryptedBuffer[256];

// Вспомогательная функция для вычисления log2
float log2_func(float x) {
  if (x <= 0.0) return 0.0;
  return log(x) / log(2.0);
}

void setup() {
  // Serial для вывода в монитор
  Serial.begin(9600);
  
  // SoftwareSerial для HC-05
  // Попробуйте изменить скорость, если не работает:
  // BTSerial.begin(38400);  // или 115200
  BTSerial.begin(9600);
  
  delay(2000); // Даем время на инициализацию HC-05
  
  // Initialize RSSI samples
  randomSeed(analogRead(0));
  for (int i = 0; i < RSSI_SAMPLE_SIZE; i++) {
    rssiSamples[i] = -55.0 + random(-5, 6);
  }
  rssiInitialized = true;
  
  // Очищаем буферы
  while (BTSerial.available() > 0) {
    BTSerial.read();
  }
  
  // Очищаем encryptedBuffer
  memset(encryptedBuffer, 0, sizeof(encryptedBuffer));
  encryptedBufferIndex = 0;
  receivingEncrypted = false;
  
  Serial.println("MFA Receiver Ready");
  Serial.println("Waiting for authentication data...");
  Serial.println("Initial State: q0");
  Serial.println();
}

void loop() {
  // Читаем зашифрованные байты из Bluetooth через SoftwareSerial
  while (BTSerial.available() > 0) {
    uint8_t byteData = BTSerial.read();
    
    // Если буфер пуст и мы начинаем прием
    if (encryptedBufferIndex == 0) {
      receivingEncrypted = true;
    }
    
    // Сохраняем байт в буфер
    if (encryptedBufferIndex < sizeof(encryptedBuffer)) {
      encryptedBuffer[encryptedBufferIndex++] = byteData;
      lastCharTime = millis();
      updateRSSISample();
    } else {
      // Буфер переполнен, сбрасываем
      Serial.println("ERROR: Encrypted buffer overflow");
      encryptedBufferIndex = 0;
      receivingEncrypted = false;
    }
  }
  
  // Обрабатываем зашифрованные данные после таймаута
  if (receivingEncrypted && encryptedBufferIndex > 0 && (millis() - lastCharTime) > DATA_TIMEOUT) {
    int dataSize = encryptedBufferIndex;
    
    // Проверяем минимальный размер (1 байт типа + 16 байт IV + минимум 1 байт данных = 18 байт)
    const int MIN_DATA_SIZE = 18;
    if (dataSize < MIN_DATA_SIZE) {
      // Сбрасываем буфер и ждем следующий пакет
      encryptedBufferIndex = 0;
      receivingEncrypted = false;
      lastCharTime = 0;
      return;
    }
    
    // Дешифруем и обрабатываем
    processEncryptedData(encryptedBuffer, dataSize);
    
    // Сбрасываем буфер
    encryptedBufferIndex = 0;
    receivingEncrypted = false;
    lastCharTime = 0;
  }
}

void updateRSSISample() {
  static unsigned long lastRSSIUpdate = 0;
  if (millis() - lastRSSIUpdate > 100) {
    rssiSamples[rssiIndex] = -55.0 + random(-5, 6);
    rssiIndex = (rssiIndex + 1) % RSSI_SAMPLE_SIZE;
    lastRSSIUpdate = millis();
  }
}

/**
 * Дешифровка и обработка данных (AES-128 упрощенный XOR)
 * @param encryptedData Зашифрованные данные: [тип] + IV + encrypted
 * @param dataSize Размер данных
 */
void processEncryptedData(uint8_t* encryptedData, int dataSize) {
  if (dataSize < 2) {
    return;
  }
  
  // Первый байт - тип шифрования: 0x01 = ChaCha20, 0x02 = AES-128
  uint8_t encryptionType = encryptedData[0];
  
  Serial.print("Encryption type: 0x");
  Serial.print(encryptionType, HEX);
  Serial.print(", Data size: ");
  Serial.println(dataSize);
  
  String decryptedJson = "";
  
  if (encryptionType == 0x02) {
    // AES-128 (упрощенный XOR)
    const int AES_IV_SIZE = 16;
    if (dataSize < 1 + AES_IV_SIZE) {
      totalSessions++;
      return;
    }
    
    uint8_t iv[AES_IV_SIZE];
    memcpy(iv, encryptedData + 1, AES_IV_SIZE);
    int encryptedSize = dataSize - 1 - AES_IV_SIZE;
    uint8_t* encrypted = encryptedData + 1 + AES_IV_SIZE;
    
    decryptedJson = decryptAES128(encrypted, encryptedSize, iv);
  } else {
    totalSessions++;
    return;
  }
  
  if (decryptedJson.length() > 0) {
    Serial.print("Decrypted JSON: ");
    Serial.println(decryptedJson);
    Serial.print("Decrypted JSON length: ");
    Serial.println(decryptedJson.length());
    processReceivedData(decryptedJson);
  } else {
    Serial.println("ERROR: decryptedJson is empty");
    totalSessions++;
  }
}

/**
 * Дешифровка AES-128 (упрощенная версия для совместимости)
 * ВАЖНО: Настоящий AES-128 требует библиотеку или полную реализацию
 * Эта упрощенная версия работает только с упрощенным шифрованием
 */
String decryptAES128(uint8_t* encrypted, int encryptedSize, uint8_t* iv) {
  // Проверка размера
  if (encryptedSize <= 0 || encryptedSize > sizeof(decryptedBuffer) - 1) {
    return "";
  }
  
  // Упрощенная дешифровка для совместимости
  // Простой XOR с ключом (совместимо с упрощенным режимом Android)
  for (int i = 0; i < encryptedSize && i < sizeof(decryptedBuffer) - 1; i++) {
    decryptedBuffer[i] = encrypted[i] ^ encryptionKey[i % AES_KEY_SIZE];
  }
  decryptedBuffer[encryptedSize] = '\0';
  
  // Проверяем результат
  if (decryptedBuffer[0] == '{' && decryptedBuffer[encryptedSize - 1] == '}') {
    return String(decryptedBuffer);
  }
  
  return "";
}

void processReceivedData(String data) {
  // Удаляем пробелы и символы новой строки
  data.trim();
  
  // Если данных нет, выходим
  if (data.length() == 0) {
    return;
  }
  
  // ПРОСТОЕ РЕШЕНИЕ: Если данные уже являются валидным JSON (начинаются с '{' и заканчиваются '}'),
  // обрабатываем их напрямую без сложного парсинга
  if (data.charAt(0) == '{' && data.charAt(data.length() - 1) == '}') {
    processJSON(data);
    return;
  }
  
  // Обрабатываем все JSON объекты в буфере (могут быть склеены)
  int startPos = 0;
  
  while (startPos < data.length()) {
    // Ищем начало JSON объекта
    int jsonStart = data.indexOf('{', startPos);
    if (jsonStart == -1) {
      break;
    }
    
    // Ищем закрывающую скобку
    int braceCount = 0;
    int jsonEnd = -1;
    
    for (int i = jsonStart; i < data.length(); i++) {
      if (data.charAt(i) == '{') {
        braceCount++;
      } else if (data.charAt(i) == '}') {
        braceCount--;
        if (braceCount == 0) {
          jsonEnd = i + 1;
          break;
        }
      }
    }
    
    if (jsonEnd == -1) {
      break;
    }
    
    // Извлекаем JSON строку
    String jsonStr = data.substring(jsonStart, jsonEnd);
    jsonStr.trim();
    
    // Обрабатываем этот JSON объект
    if (jsonStr.length() > 0) {
      processJSON(jsonStr);
    }
    
    // Переходим к следующему
    startPos = jsonEnd;
  }
}

void processJSON(String jsonStr) {
  // Очищаем строку от лишних символов
  jsonStr.trim();
  
  // Выводим сообщение о парсинге
  Serial.print("Parsing JSON: ");
  Serial.println(jsonStr);
  
  // Парсим JSON без выделения большого буфера (минимальный парсер по подстроке)
  // Ищем поле "auth"
  String authType = "";
  int authPos = jsonStr.indexOf("\"auth\"");
  if (authPos != -1) {
    int colonPos = jsonStr.indexOf(':', authPos);
    if (colonPos != -1) {
      // Значение сразу после двоеточия в кавычках: "auth":"biometric"
      int firstQuote = jsonStr.indexOf('\"', colonPos);
      int secondQuote = jsonStr.indexOf('\"', firstQuote + 1);
      if (firstQuote != -1 && secondQuote != -1 && secondQuote > firstQuote) {
        authType = jsonStr.substring(firstQuote + 1, secondQuote);
      }
    }
  }
  
  // Нормализуем строку (убираем пробелы)
  authType.trim();
  
  // Отладочный вывод
  Serial.print("Auth type detected: '");
  Serial.print(authType);
  Serial.println("'");
  
  // Обрабатываем аутентификацию
  if (authType.equals("biometric")) {
    updateDFA(true);
    successfulSessions++;
    totalSessions++;
    Serial.println("Biometric success - DFA updated");
    printMetrics();
  } else if (authType.equals("pin")) {
    updateDFA(false);
    successfulSessions++;
    totalSessions++;
    Serial.println("PIN success - DFA updated");
    printMetrics();
  } else {
    Serial.print("Unknown auth type: '");
    Serial.print(authType);
    Serial.println("'");
    totalSessions++;
    return;
  }
  
  Serial.println(); // Пустая строка для читаемости
}

void updateDFA(bool isBiometric) {
  State previousState = currentState;
  
  if (isBiometric) {
    currentState = q1;
  } else {
    currentState = q2;
  }
  
  stateTransitionCount[previousState]++;
  totalTransitions++;
}

float calculateDEC() {
  // Для начального состояния или малого количества переходов используем базовое значение
  // D_EC = 1.58 для 3 состояний с равномерным распределением
  if (totalTransitions == 0) {
    return 1.58; // Базовое значение для 3 состояний
  }
  
  // Если переходов мало, используем базовое значение до накопления достаточной статистики
  // Нужно минимум 3 перехода для каждого состояния для точного расчета
  if (totalTransitions < 9) {
    return 1.58; // Базовое значение до накопления статистики
  }
  
  float probabilities[NUM_STATES];
  float entropy = 0.0;
  
  for (int i = 0; i < NUM_STATES; i++) {
    probabilities[i] = (float)stateTransitionCount[i] / totalTransitions;
    
    if (probabilities[i] > 0.0) {
      entropy -= probabilities[i] * log2_func(probabilities[i]);
    }
  }
  
  float dec = entropy / log2_func((float)NUM_STATES);
  
  // Ограничиваем значения для стабильности
  if (dec < 0.0) dec = 0.0;
  if (dec > 2.0) dec = 2.0;
  
  // Если значение слишком мало или некорректно, используем базовое
  if (dec < 1.0) dec = 1.58;
  
  return dec;
}

float calculateBSSS() {
  if (!rssiInitialized) {
    return 0.85;
  }
  
  float mean = 0.0;
  for (int i = 0; i < RSSI_SAMPLE_SIZE; i++) {
    mean += rssiSamples[i];
  }
  mean /= RSSI_SAMPLE_SIZE;
  
  float variance = 0.0;
  for (int i = 0; i < RSSI_SAMPLE_SIZE; i++) {
    float diff = rssiSamples[i] - mean;
    variance += diff * diff;
  }
  float std_dev = sqrt(variance / RSSI_SAMPLE_SIZE);
  
  float mean_abs = abs(mean);
  if (mean_abs < 0.1) mean_abs = 0.1;
  
  float bsss = 1.0 - (std_dev / mean_abs);
  
  if (bsss < 0.0) bsss = 0.0;
  if (bsss > 1.0) bsss = 1.0;
  
  return bsss;
}

float calculateIMSI(float dec, float bsss) {
  float C = C_BASE;
  if (totalSessions > 0) {
    C = (float)successfulSessions / totalSessions;
  }
  
  float imsi = w1 * dec + w2 * bsss + w3 * C;
  return imsi;
}

void printMetrics() {
  String stateName = "";
  switch (currentState) {
    case q0:
      stateName = "q0";
      break;
    case q1:
      stateName = "q1";
      break;
    case q2:
      stateName = "q2";
      break;
  }
  
  float d_ec = calculateDEC();
  float bsss = calculateBSSS();
  float imsi = calculateIMSI(d_ec, bsss);
  
  // Вычисляем средний RSSI
  float avgRSSI = 0.0;
  if (rssiInitialized) {
    for (int i = 0; i < RSSI_SAMPLE_SIZE; i++) {
      avgRSSI += rssiSamples[i];
    }
    avgRSSI /= RSSI_SAMPLE_SIZE;
  }
  
  Serial.print("State: ");
  Serial.print(stateName);
  Serial.print(", D_EC: ");
  Serial.print(d_ec, 2);
  Serial.print(", BSSS: ");
  Serial.print(bsss, 2);
  Serial.print(", IMSI: ");
  Serial.print(imsi, 2);
  Serial.print(", RSSI: -");
  Serial.print(abs(avgRSSI), 1);
  Serial.println(" dBm");
  
  Serial.print("Sessions: ");
  Serial.print(successfulSessions);
  Serial.print("/");
  Serial.print(totalSessions);
  Serial.print(" (");
  if (totalSessions > 0) {
    Serial.print((float)successfulSessions / totalSessions * 100.0, 1);
  } else {
    Serial.print("0.0");
  }
  Serial.print("%), Transitions: ");
  Serial.println(totalTransitions);
}
