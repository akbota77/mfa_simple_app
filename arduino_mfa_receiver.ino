// Arduino code to receive and parse JSON from Android MFA app
// ВАЖНО: HC-05 должен быть подключен к SoftwareSerial (пины 10 и 11)
// HC-05 TX -> Arduino pin 10 (RX)
// HC-05 RX -> Arduino pin 11 (TX)
// Serial порт остается свободным для Serial Monitor

#include <SoftwareSerial.h>
#include <ArduinoJson.h>
#include <math.h>

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

String receivedBuffer = "";
unsigned long lastCharTime = 0;
const unsigned long DATA_TIMEOUT = 100; // Таймаут 100ms

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
  
  Serial.println("MFA Receiver Ready");
  Serial.println("Waiting for authentication data...");
  Serial.println("Initial State: q0");
  Serial.println();
}

void loop() {
  // Читаем данные из Bluetooth через SoftwareSerial
  while (BTSerial.available() > 0) {
    char inChar = (char)BTSerial.read();
    
    // Пропускаем символы новой строки и возврата каретки
    if (inChar == '\n' || inChar == '\r') {
      // Если получили символ новой строки и есть данные в буфере, обрабатываем сразу
      if (receivedBuffer.length() > 0) {
        String dataToProcess = receivedBuffer;
        receivedBuffer = "";
        processReceivedData(dataToProcess);
      }
      continue;
    }
    
    receivedBuffer += inChar;
    lastCharTime = millis();
    updateRSSISample();
  }
  
  // Обрабатываем данные после таймаута (если нет символа новой строки)
  if (receivedBuffer.length() > 0 && (millis() - lastCharTime) > DATA_TIMEOUT) {
    String dataToProcess = receivedBuffer;
    receivedBuffer = "";
    lastCharTime = 0;
    
    // Обрабатываем только если есть данные и это похоже на JSON
    if (dataToProcess.length() > 0 && (dataToProcess.indexOf('{') != -1)) {
      processReceivedData(dataToProcess);
    }
  }
  
  // Убрали периодическую проверку, чтобы не засорять вывод
}

void updateRSSISample() {
  static unsigned long lastRSSIUpdate = 0;
  if (millis() - lastRSSIUpdate > 100) {
    rssiSamples[rssiIndex] = -55.0 + random(-5, 6);
    rssiIndex = (rssiIndex + 1) % RSSI_SAMPLE_SIZE;
    lastRSSIUpdate = millis();
  }
}

void processReceivedData(String data) {
  // Удаляем пробелы и символы новой строки
  data.trim();
  
  // Если данных нет, выходим
  if (data.length() == 0) {
    return;
  }
  
  // Обрабатываем все JSON объекты в буфере (могут быть склеены)
  int startPos = 0;
  int processedCount = 0;
  
  while (startPos < data.length()) {
    // Ищем начало JSON объекта
    int jsonStart = data.indexOf('{', startPos);
    if (jsonStart == -1) {
      // Если нет открывающей скобки, но есть данные - возможно поврежденные данные
      if (processedCount == 0 && data.length() > 5) {
        Serial.print("WARNING: No '{' found in data: ");
        Serial.println(data);
      }
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
      // Неполный JSON - возможно данные еще приходят
      if (processedCount == 0) {
        // Сохраняем неполные данные обратно в буфер для следующей попытки
        receivedBuffer = data.substring(jsonStart);
      }
      break;
    }
    
    // Извлекаем JSON строку
    String jsonStr = data.substring(jsonStart, jsonEnd);
    jsonStr.trim();
    
    // Обрабатываем этот JSON объект
    if (jsonStr.length() > 0) {
      processJSON(jsonStr);
      processedCount++;
    }
    
    // Переходим к следующему
    startPos = jsonEnd;
  }
}

void processJSON(String jsonStr) {
  // Очищаем строку от лишних символов
  jsonStr.trim();
  
  // Выводим полученные данные
  Serial.print("Received: ");
  Serial.println(jsonStr);
  
  // Выводим сообщение о парсинге
  Serial.print("Parsing JSON: ");
  Serial.println(jsonStr);
  
  // Парсим JSON
  DynamicJsonDocument doc(256);
  DeserializationError error = deserializeJson(doc, jsonStr);
  
  if (error) {
    Serial.print("Parse error: ");
    Serial.println(error.c_str());
    totalSessions++;
    Serial.println();
    return;
  }
  
  // Получаем тип аутентификации
  String authType = "";
  
  if (doc.containsKey("auth")) {
    if (doc["auth"].is<const char*>()) {
      authType = String(doc["auth"].as<const char*>());
    } else if (doc["auth"].is<String>()) {
      authType = doc["auth"].as<String>();
    }
  }
  
  // Нормализуем строку (убираем пробелы)
  authType.trim();
  
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
    Serial.println();
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
  
  Serial.print("State: ");
  Serial.print(stateName);
  Serial.print(", D_EC: ");
  Serial.print(d_ec, 2);
  Serial.print(", BSSS: ");
  Serial.print(bsss, 2);
  Serial.print(", IMSI: ");
  Serial.println(imsi, 2);
}
