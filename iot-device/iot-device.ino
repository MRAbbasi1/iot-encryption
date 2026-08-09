#include <Wire.h>
#include <Adafruit_BMP085.h>
#include "DHT.h"
#include <WiFi.h>
#include <time.h>
#include <ArduinoJson.h>
#include "mbedtls/gcm.h"
#include <HTTPClient.h>
#include "env.h"

const char *ntpServer = "pool.ntp.org";
const long gmtOffset_sec = 0;
const int daylightOffset_sec = 0;

#define DHT1_PIN 4
#define DHT2_PIN 5
#define DHTTYPE DHT22

DHT dht1(DHT1_PIN, DHTTYPE);
DHT dht2(DHT2_PIN, DHTTYPE);
Adafruit_BMP085 bmp;

const String device_id = DEVICE_ID;

String bytesToHex(const unsigned char *data, size_t length)
{
  String hexString = "";
  for (size_t i = 0; i < length; i++)
  {
    if (data[i] < 0x10)
      hexString += "0";
    hexString += String(data[i], HEX);
  }
  return hexString;
}

// ----------------------------------------------------
void setup()
{
  Serial.begin(115200);
  Serial.println("\n--- Starting IoT Device---");

  // Initialize sensors
  dht1.begin();
  dht2.begin();
  bmp.begin();

  // WiFi connection
  Serial.print("Connecting to WiFi: ");
  Serial.println(WIFI_SSID);

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED)
  {
    delay(500);
    Serial.print(".");
  }

  if (WiFi.status() == WL_CONNECTED)
  {
    Serial.println("\nWiFi connected!");
    Serial.println("IP address: " + WiFi.localIP().toString());
    Serial.println("Signal strength: " + String(WiFi.RSSI()) + " dBm");
  }
  else
  {
    Serial.println("\nError: WiFi connection failed.");
  }

  // UTC time synchronization
  Serial.print("Syncing time with NTP");
  configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);
  struct tm timeinfo;

  while (!getLocalTime(&timeinfo))
  {
    delay(500);
    Serial.print(".");
  }

  if (getLocalTime(&timeinfo))
  {
    Serial.println("\nTime synchronized: " + String(asctime(&timeinfo)));
  }
  else
  {
    Serial.println("\nError: Time synchronization failed.");
  }
}

// ----------------------------------------------------
void loop()
{
  Serial.println("\n--- New Reading Cycle ---");

  // Read sensor data
  float humidity = dht1.readHumidity();
  float temperature = dht2.readTemperature();
  float pressure = bmp.readPressure();

  // Update time
  time_t now;
  time(&now);

  // Create JSON payload
  StaticJsonDocument<200> doc;
  doc["device_id"] = device_id;
  doc["timestamp"] = now;
  doc["temperature"] = temperature;
  doc["humidity"] = humidity;
  doc["pressure"] = pressure;

  // Serialize JSON to string
  String jsonString;
  serializeJson(doc, jsonString);
  Serial.println("Plain JSON: " + jsonString);

  // Encrypt the JSON payload using AES-256-GCM
  size_t plaintext_len = jsonString.length();
  const unsigned char *plaintext = (const unsigned char *)jsonString.c_str();
  unsigned char ciphertext[plaintext_len];
  unsigned char iv[12];
  unsigned char tag[16];

  // Generate a random IV
  for (int i = 0; i < 12; i++)
  {
    iv[i] = esp_random() % 256; // 32-bit random number devided by 256 to get a 12-byte(96-bit)
  }

  // Initialize GCM context and set the AES key
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, AES_KEY, 256);

  // Encrypt and generate authentication tag
  // (GCM context, Operation mode, Length of plaintext,
  // IV, IV length, Additional data, Additional data length, Plaintext, Ciphertext, Tag length, Tag)
  mbedtls_gcm_crypt_and_tag(
      &ctx, MBEDTLS_GCM_ENCRYPT, plaintext_len,
      iv, 12, NULL, 0, plaintext, ciphertext, 16, tag);

  mbedtls_gcm_free(&ctx);

  // Create a JSON payload for the encrypted data
  StaticJsonDocument<512> securePayloadDoc;
  securePayloadDoc["iv"] = bytesToHex(iv, 12);
  securePayloadDoc["ciphertext"] = bytesToHex(ciphertext, plaintext_len);
  securePayloadDoc["tag"] = bytesToHex(tag, 16);

  // Serialize the secure payload to a string
  String finalPayload;
  serializeJson(securePayloadDoc, finalPayload);
  Serial.println("Encrypted JSON: " + finalPayload);

  // Send the encrypted payload to the server
  if (WiFi.status() == WL_CONNECTED)
  {
    HTTPClient http;
    http.begin(SERVER_URL);
    http.addHeader("Content-Type", "application/json");

    Serial.println("Sending data to server...");
    int httpResponseCode = http.POST(finalPayload);

    Serial.println("HTTP Status: " + String(httpResponseCode));
    http.end();
  }
  else
  {
    Serial.println("Warning: WiFi disconnected. Cannot send data.");
  }

  delay(30000); // 30 seconds delay for every cycle
}