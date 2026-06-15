#define CONFIG_SPIRAM_SUPPORT 1
#include <TFT_eSPI.h>
#include <SPI.h>
#include <Wire.h>

// #define DISABLE_BLE 1

// #ifndef DISABLE_BLE
#include <NimBLEDevice.h>
// #endif

#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <SD.h>
#include <FS.h>
#include "boot.h"
#include "types.h"
#include "WebUI.h"
#include "squirrel_egg.h"
#include "oui.h"
#include "pentest.h"
#include "modules/presence_radar/presence_radar.h"

// ======================================================
// CONSTANTS
// ======================================================

#define MAX_DEVICES        100
#define MAX_KNOWN_DEVICES  500
#define DEVICE_TIMEOUT_MS  12000
#define CLEANUP_TIMEOUT_MS 15000
#define SCAN_INTERVAL_MS   2500
#define DRAW_INTERVAL_MS   80
#define PULSE_INTERVAL_MS  120
#define TOUCH_DEBOUNCE_MS  150
#define MAX_LOG_SIZE       51200
#define SWEEP_STEP         5

#define RSSI_FLOOR    -100
#define RSSI_CEIL     -30
#define RSSI_STRONG   -60
#define RSSI_HIGH_RISK -55
#define RSSI_CRITICAL -45

// ======================================================
// WIFI AP CACHE (for WiFi Hunt mode)
// ======================================================

#define MAX_CACHED_APS 40

struct CachedAP {
    char bssid[18];
    char ssid[24];
    int8_t rssi;
    int8_t channel;
    unsigned long lastSeen;
};
CachedAP cachedAPs[MAX_CACHED_APS];
int cachedAPCount = 0;

// ======================================================
// DISPLAY
// ======================================================

TFT_eSPI tft = TFT_eSPI();
TFT_eSprite frameBuffer = TFT_eSprite(&tft);

// ======================================================
// PINS (raw GPIO numbers — board-independent)
// ======================================================
// XIAO ESP32C5 mapping:
// D0=GPIO1, D1=GPIO0, D2=GPIO25, D3=GPIO7,
// D4=GPIO23(SDA), D5=GPIO24(SCL), D6=GPIO11(TX), D7=GPIO12(RX),
// D8=GPIO8(SCK), D9=GPIO9(MISO), D10=GPIO10(MOSI)

#define TOUCH_SDA 23   // D4
#define TOUCH_SCL 24   // D5
#define TOUCH_RST -1
#define TOUCH_IRQ 12   // D7

// Touch controller is CHSC6X on the Seeed Round Display (I2C addr 0x2E, INT pin driven LOW when pressed)
// No CST816S library needed — we poll the INT pin directly

#define TFT_BL     11  // D6 — display backlight (GC9A01 BL pin on Seeed Round Display)
#define BUZZER_PIN 26  // JST pin 2 (BAT_VOLT_PIN_EN — safe as buzzer output when not using batt monitoring)
#define SD_CS      1   // D0

// ======================================================
// MODES
// ======================================================

ScanMode currentMode = BLE_MODE;

AppState appState = APP_MENU;
int menuIndex = 0;
const char* menuItems[] = {"BLE Scan", "WiFi Scan", "Config AP", "Deauth", "Tripwire", "BLE Hunt", "WIFI Hunt", "Evil Twin", "MAC Rand", "Presence Radar", "About"};
const int menuCount = 11;

// ======================================================
// SCAN RESULT QUEUE (producer: BLE callback / consumer: loop)
// ======================================================

#define RESULT_QUEUE_SIZE 32

struct ScanResult {
    char mac[18];
    char name[24];
    int8_t rssi;
};

ScanResult resultQueue[RESULT_QUEUE_SIZE];
volatile int resultQueueHead = 0;
volatile int resultQueueTail = 0;


// ======================================================
// STORAGE
// ======================================================

DeviceInfo devices[MAX_DEVICES];
int deviceCount = 0;

char knownDevices[MAX_KNOWN_DEVICES][18];
int knownDeviceCount = 0;

bool newDeviceDetected = false;
int totalLogs = 0;
bool sdReady = false;

#ifndef DISABLE_BLE
NimBLEScan* pBLEScan = nullptr;
#endif

// ======================================================
// TARGET TRACKING
// ======================================================

int activeTargetIndex = -1;
unsigned long targetPulseTimer = 0;
int pulseSize = 0;

// ======================================================
// TIMERS
// ======================================================

int sweepAngle = 0;
int prevSweepX = 120, prevSweepY = 215; // initial sweep line endpoint
int wifiScrollOffset = 0;
unsigned long lastScan = 0;
unsigned long alertTimer = 0;
unsigned long beepTimer = 0;
unsigned long lastTouchMs = 0;

// Easter egg: tap 10 times to show secret image
#define EASTER_EGG_TAPS 10
static int easterTapCount = 0;
static unsigned long lastEasterTapMs = 0;
static int configTapCount = 0;

// Deauth easter egg (hold About screen)
static volatile unsigned long deauthCount = 0;
static volatile bool deauthDetected = false;
static char deauthLastSrc[18] = "none";
static bool deauthActive = false;
static unsigned long deauthFlashUntil = 0;
static bool deauthDrawn = false;
static int deauthChannel = 1;
static unsigned long deauthChanTimer = 0;

extern "C" void deauthSnifferCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint8_t *frame = pkt->payload;
    if ((frame[0] & 0xFC) == 0xC0 || (frame[0] & 0xFC) == 0xA0) {
        deauthCount++;
        snprintf(deauthLastSrc, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
            frame[10], frame[11], frame[12], frame[13], frame[14], frame[15]);
        deauthDetected = true;
    }
}

// ======================================================
// DIGITAL TAILS (persistent device tracking)
// ======================================================

#define TAILS_WINDOW 18
#define TAILS_STRONG_RSSI -55
#define TAILS_WATCH_MIN 10
#define TAILS_ALERT_MIN 12
#define TAILS_MAX_SHOW 8
#define TAILS_MAX_TRACKED 100
#define TAILS_SCAN_INTERVAL_MS 2000
#define TAILS_BEEP_COOLDOWN_MS 10000

struct TailSlot {
    char mac[18];
    uint32_t bitmask;
    int seenCount;
};
static TailSlot tailSlots[TAILS_MAX_TRACKED];
static int tailSlotCount = 0;
static unsigned long tailsLastScan = 0;
static bool tailsDrawn = false;
static unsigned long tailsBeepTimer = 0;

int tripwirePhase = 1;
int tripwireBaselineCount = 0;
int tripwireAlertCount = 0;
int tripwireStrongestRssi = -100;
char tripwireStrongestMac[18] = "";
char tripwireLastNewMac[18] = "";
char tripwireStrongestName[24] = "";

static int popcount(uint32_t x) {
    int c = 0;
    while (x) { c += x & 1; x >>= 1; }
    return c;
}

static int tailsBarValue(int rssi) {
    if (rssi >= -35) return 10;
    if (rssi >= -40) return 9;
    if (rssi >= -45) return 8;
    if (rssi >= -50) return 7;
    if (rssi >= -55) return 6;
    if (rssi >= -60) return 5;
    if (rssi >= -65) return 4;
    if (rssi >= -70) return 3;
    if (rssi >= -80) return 2;
    return 1;
}

static int findTailSlot(const char* mac) {
    for (int i = 0; i < tailSlotCount; i++) {
        if (strcmp(tailSlots[i].mac, mac) == 0) return i;
    }
    return -1;
}

static void updateTails() {
    for (int i = 0; i < tailSlotCount; i++) {
        tailSlots[i].bitmask = (tailSlots[i].bitmask << 1) & 0x3FFFF;
        tailSlots[i].seenCount = popcount(tailSlots[i].bitmask);
    }
    for (int d = 0; d < deviceCount; d++) {
        const char* mac = devices[d].mac;
        int t = findTailSlot(mac);
        if (t < 0) {
            if (tailSlotCount >= TAILS_MAX_TRACKED) continue;
            t = tailSlotCount++;
            strncpy(tailSlots[t].mac, mac, 17);
            tailSlots[t].mac[17] = '\0';
            tailSlots[t].bitmask = 0;
        }
        tailSlots[t].bitmask |= 1;
        tailSlots[t].seenCount = popcount(tailSlots[t].bitmask);
    }
}

static int getTailRssi(const char* mac) {
    for (int i = 0; i < deviceCount; i++) {
        if (strcmp(devices[i].mac, mac) == 0) return devices[i].rssi;
    }
    return -100;
}

static const char* getTailName(const char* mac) {
    for (int i = 0; i < deviceCount; i++) {
        if (strcmp(devices[i].mac, mac) == 0) return devices[i].name;
    }
    return "";
}

static void drawTailsScreen() {
    frameBuffer.fillScreen(TFT_BLACK);

    // Find top tail
    int bestIdx = -1, bestSeen = -1, bestRssi = -100;
    for (int i = 0; i < tailSlotCount; i++) {
        int s = tailSlots[i].seenCount;
        if (s == 0) continue;
        int r = getTailRssi(tailSlots[i].mac);
        if (s > bestSeen || (s == bestSeen && r > bestRssi)) {
            bestSeen = s; bestRssi = r; bestIdx = i;
        }
    }

    // Title
    frameBuffer.setTextSize(2);
    frameBuffer.setTextColor(TFT_GREEN);
    frameBuffer.setCursor(80, 6);
    frameBuffer.print("TAILS");

    // Status + confidence
    const char* status = "SCANNING";
    unsigned int statusColor = TFT_WHITE;
    if (bestSeen >= TAILS_ALERT_MIN && bestRssi >= TAILS_STRONG_RSSI) {
        status = "ALERT"; statusColor = TFT_RED;
    } else if (bestSeen >= TAILS_WATCH_MIN) {
        status = "WATCH"; statusColor = TFT_YELLOW;
    }

    int score = 0;
    if (bestSeen >= TAILS_ALERT_MIN) score += 2;
    else if (bestSeen >= TAILS_WATCH_MIN) score += 1;
    if (bestRssi >= TAILS_STRONG_RSSI) score += 2;
    else if (bestRssi >= -65) score += 1;
    if (tailSlotCount > 10) score += 1;
    const char* conf = (score >= 5) ? "HIGH" : (score >= 3) ? "MED" : "LOW";

    frameBuffer.setTextSize(1);
    frameBuffer.setTextColor(statusColor);
    frameBuffer.setCursor(50, 28);
    frameBuffer.print(status);
    frameBuffer.setTextColor(TFT_CYAN);
    frameBuffer.setCursor(82, 28);
    frameBuffer.printf("CONF:%s", conf);

    // Stats line
    frameBuffer.setTextColor(TFT_WHITE);
    frameBuffer.setCursor(50, 44);
    if (bestIdx >= 0) {
        frameBuffer.printf("Tail: %d/%d", bestSeen, TAILS_WINDOW);
        frameBuffer.setCursor(128, 44);
        frameBuffer.printf("Devs: %d", tailSlotCount);
    } else {
        frameBuffer.print("Building window...");
    }

    // RSSI bar + name for top tail
    if (bestIdx >= 0) {
        int bv = tailsBarValue(bestRssi);
        frameBuffer.setTextColor(TFT_WHITE);
        frameBuffer.setCursor(50, 60);
        frameBuffer.printf("RSSI: %d dBm", bestRssi);
        frameBuffer.setCursor(50, 74);
        unsigned int barColor;
        if (bestRssi >= -55) barColor = TFT_RED;
        else if (bestRssi >= -65) barColor = TFT_ORANGE;
        else if (bestRssi >= -75) barColor = TFT_YELLOW;
        else barColor = TFT_GREEN;
        frameBuffer.setTextColor(barColor);
        for (int b = 0; b < bv; b++) frameBuffer.print("#");
        for (int b = bv; b < 10; b++) frameBuffer.print("-");

        const char* nm = getTailName(tailSlots[bestIdx].mac);
        if (nm && nm[0]) {
            frameBuffer.setTextColor(TFT_GREEN);
            frameBuffer.setCursor(30, 90);
            char buf[13];
            strncpy(buf, nm, 12);
            buf[12] = '\0';
            frameBuffer.print(buf);
        }
    }

    // Separator
    frameBuffer.setTextColor(TFT_DARKGREEN);
    frameBuffer.setCursor(50, 106);
    frameBuffer.print("--- Top Tails ---");

    // Gather and sort top tails
    struct TailEntry { int idx; int seen; int rssi; char mac[18]; int bars; };
    TailEntry sorted[TAILS_MAX_SHOW];
    int sortedCount = 0;
    for (int i = 0; i < tailSlotCount && sortedCount < TAILS_MAX_SHOW; i++) {
        if (tailSlots[i].seenCount == 0) continue;
        int r = getTailRssi(tailSlots[i].mac);
        int pos = sortedCount;
        while (pos > 0 && (tailSlots[i].seenCount > sorted[pos-1].seen ||
               (tailSlots[i].seenCount == sorted[pos-1].seen && r > sorted[pos-1].rssi)))
            pos--;
        if (pos < TAILS_MAX_SHOW) {
            if (sortedCount < TAILS_MAX_SHOW) sortedCount++;
            for (int j = sortedCount - 1; j > pos; j--) sorted[j] = sorted[j-1];
            sorted[pos].idx = i;
            sorted[pos].seen = tailSlots[i].seenCount;
            sorted[pos].rssi = r;
            strncpy(sorted[pos].mac, tailSlots[i].mac, 17);
            sorted[pos].mac[17] = '\0';
            sorted[pos].bars = tailsBarValue(r);
        }
    }

    // Display sorted tails
    for (int i = 0; i < sortedCount && i < TAILS_MAX_SHOW; i++) {
        int y = 118 + i * 12;
        frameBuffer.setTextSize(1);

        // Flag
        const char* flag = "  ";
        if (sorted[i].seen >= TAILS_ALERT_MIN && sorted[i].rssi >= TAILS_STRONG_RSSI) flag = "!!";
        else if (sorted[i].seen >= TAILS_WATCH_MIN) flag = "! ";

        frameBuffer.setTextColor(TFT_YELLOW);
        frameBuffer.setCursor(8, y);
        frameBuffer.print(flag);

        // Short MAC
        frameBuffer.setTextColor(sorted[i].seen >= TAILS_WATCH_MIN ? TFT_WHITE : TFT_DARKGREEN);
        frameBuffer.setCursor(28, y);
        char sm[10];
        const char* m = sorted[i].mac;
        snprintf(sm, 10, "%c%c:%c%c:%c%c:%c%c", m[9], m[10], m[12], m[13], m[15], m[16], m[0], m[1]);
        frameBuffer.print(sm);

        // Seen count
        frameBuffer.setTextColor(TFT_CYAN);
        frameBuffer.setCursor(96, y);
        frameBuffer.printf("%2d/%d", sorted[i].seen, TAILS_WINDOW);

        // RSSI
        frameBuffer.setTextColor(sorted[i].rssi >= TAILS_STRONG_RSSI ? TFT_RED : TFT_WHITE);
        frameBuffer.setCursor(150, y);
        frameBuffer.print(sorted[i].rssi);

        // Bars
        frameBuffer.setTextColor(sorted[i].rssi >= -55 ? TFT_RED : TFT_GREEN);
        frameBuffer.setCursor(178, y);
        for (int b = 0; b < sorted[i].bars; b++) frameBuffer.print("#");
    }

    frameBuffer.setTextColor(TFT_DARKGREEN);
    frameBuffer.setCursor(75, 218);
    frameBuffer.print("HOLD TO RETURN");
    frameBuffer.pushSprite(0, 0);

    // Update web-accessible globals
    tripwireBaselineCount = tailSlotCount;
    tripwireStrongestRssi = bestRssi;
    if (bestIdx >= 0) {
        strncpy(tripwireLastNewMac, tailSlots[bestIdx].mac, 17);
        tripwireLastNewMac[17] = '\0';
        const char* nm = getTailName(tailSlots[bestIdx].mac);
        if (nm && nm[0]) {
            strncpy(tripwireStrongestName, nm, 23);
            tripwireStrongestName[23] = '\0';
        } else {
            tripwireStrongestName[0] = '\0';
        }
    }
}

// ======================================================
// DEVICE HUNTER (track a single target)
// ======================================================

#define HUNTER_PICK_COUNT 8

static bool hunterDrawn = false;
static bool hunterPicking = true;
static int hunterPickIndex = 0;
static bool hunterHunting = false;
static char hunterTargetMac[18] = "";
static char hunterTargetName[24] = "";
static unsigned long hunterBeepTimer = 0;
static int hunterTargetRssi = -100;
static int hunterPrevLevel = 0;

// ======================================================
// WIFI HUNT (track a single AP)
// ======================================================

#define WIFI_HUNT_PICK_COUNT 8

static bool wifiHuntDrawn = false;
static bool wifiHuntPicking = true;
static int wifiHuntPickIndex = 0;
static bool wifiHuntHunting = false;
static char wifiHuntTargetBssid[18] = "";
static char wifiHuntTargetSsid[24] = "";
static int wifiHuntTargetRssi = -100;
static int wifiHuntPrevLevel = 0;
static unsigned long wifiHuntBeepTimer = 0;
static unsigned long wifiHuntPacketTimer = 0;
static int8_t wifiHuntTargetChannel = 0;
static unsigned long wifiHuntRedrawTimer = 0;
static uint8_t wifiHuntTargetBytes[6];
static bool wifiHuntSniffing = false;
static unsigned long wifiHuntLastSignalMs = 0;

// Convert "XX:XX:XX:XX:XX:XX" string to 6 bytes
static void parseMacBytes(const char* mac, uint8_t* out) {
    for (int i = 0; i < 6; i++) {
        out[i] = strtol(mac + i * 3, NULL, 16);
    }
}

// Fast directed scan on a single channel for target BSSID
// Returns RSSI in dBm, or -100 if target not found
static int wifiHuntFastScan() {
    if (wifiHuntTargetChannel <= 0) return -100;
    WiFi.scanDelete();
    wifi_scan_config_t cfg = {};
    cfg.ssid = NULL;
    cfg.bssid = wifiHuntTargetBytes;
    cfg.channel = wifiHuntTargetChannel;
    cfg.show_hidden = true;
    cfg.scan_type = WIFI_SCAN_TYPE_ACTIVE;
    cfg.scan_time.active.min = 80;
    cfg.scan_time.active.max = 120;
    esp_wifi_scan_start(&cfg, true);
    unsigned long start = millis();
    while (millis() - start < 300) {
        uint16_t num = 0;
        esp_wifi_scan_get_ap_num(&num);
        if (num > 0) {
            wifi_ap_record_t records[1];
            uint16_t count = 1;
            esp_wifi_scan_get_ap_records(&count, records);
            if (count > 0) {
                esp_wifi_scan_stop();
                WiFi.scanDelete();
                return records[0].rssi;
            }
        }
        delay(5);
    }
    esp_wifi_scan_stop();
    WiFi.scanDelete();
    return -100;
}

static void drawHunterPickScreen() {
    frameBuffer.fillScreen(TFT_BLACK);
    frameBuffer.setTextSize(2);
    frameBuffer.setTextColor(TFT_GREEN);
    frameBuffer.setCursor(80, 10);
    frameBuffer.print("HUNT");

    frameBuffer.setTextSize(1);
    frameBuffer.setTextColor(TFT_CYAN);
    frameBuffer.setCursor(45, 34);
    frameBuffer.print("Pick a target device:");

    // Gather top tails sorted by seen + RSSI
    struct { int idx; int seen; int rssi; char mac[18]; int bars; } list[HUNTER_PICK_COUNT];
    int lc = 0;
    for (int i = 0; i < tailSlotCount && lc < HUNTER_PICK_COUNT; i++) {
        if (tailSlots[i].seenCount == 0) continue;
        int r = getTailRssi(tailSlots[i].mac);
        int pos = lc;
        while (pos > 0 && (tailSlots[i].seenCount > list[pos-1].seen ||
               (tailSlots[i].seenCount == list[pos-1].seen && r > list[pos-1].rssi)))
            pos--;
        if (pos < HUNTER_PICK_COUNT) {
            if (lc < HUNTER_PICK_COUNT) lc++;
            for (int j = lc-1; j > pos; j--) list[j] = list[j-1];
            list[pos].idx = i;
            list[pos].seen = tailSlots[i].seenCount;
            list[pos].rssi = r;
            strncpy(list[pos].mac, tailSlots[i].mac, 17);
            list[pos].mac[17] = '\0';
            list[pos].bars = tailsBarValue(r);
        }
    }

    if (lc == 0) {
        frameBuffer.setTextColor(TFT_WHITE);
        frameBuffer.setCursor(25, 80);
        frameBuffer.print("No devices tracked yet.");
        frameBuffer.setCursor(25, 100);
        frameBuffer.print("Run Tripwire first to");
        frameBuffer.setCursor(25, 120);
        frameBuffer.print("build a tail history.");
        frameBuffer.setTextColor(TFT_DARKGREEN);
        frameBuffer.setCursor(65, 218);
        frameBuffer.print("HOLD TO RETURN");
        return;
    }

    int visible = min(lc, 6);
    int startY = 52;
    int itemH = 22;
    int highlightStart = constrain(hunterPickIndex - 2, 0, max(0, lc - visible));

    for (int i = 0; i < visible; i++) {
        int idx = highlightStart + i;
        if (idx >= lc) break;
        int y = startY + i * itemH;
        bool sel = (idx == hunterPickIndex);
        if (sel) {
            frameBuffer.fillRoundRect(8, y-2, 224, itemH+2, 4, frameBuffer.color565(30, 60, 30));
        }
        const char* flag = (list[idx].seen >= TAILS_ALERT_MIN && list[idx].rssi >= TAILS_STRONG_RSSI) ? "!!" :
                           (list[idx].seen >= TAILS_WATCH_MIN) ? "!" : "  ";
        frameBuffer.setTextColor(sel ? TFT_GREEN : TFT_YELLOW);
        frameBuffer.setCursor(12, y);
        frameBuffer.print(flag);

        const char* m = list[idx].mac;
        char sm[10];
        snprintf(sm, 10, "%c%c:%c%c:%c%c:%c%c", m[9], m[10], m[12], m[13], m[15], m[16], m[0], m[1]);
        frameBuffer.setTextColor(TFT_WHITE);
        frameBuffer.setCursor(30, y);
        frameBuffer.print(sm);
        frameBuffer.setTextColor(TFT_CYAN);
        frameBuffer.setCursor(108, y);
        frameBuffer.printf("%2d/%d", list[idx].seen, TAILS_WINDOW);
        frameBuffer.setTextColor(list[idx].rssi >= TAILS_STRONG_RSSI ? TFT_RED : TFT_WHITE);
        frameBuffer.setCursor(156, y);
        frameBuffer.print(list[idx].rssi);
        frameBuffer.setTextColor(list[idx].rssi >= -55 ? TFT_RED : TFT_GREEN);
        frameBuffer.setCursor(180, y);
        for (int b = 0; b < list[idx].bars; b++) frameBuffer.print("#");
    }

    frameBuffer.setTextColor(TFT_DARKGREEN);
    frameBuffer.setCursor(45, 218);
    frameBuffer.print("HOLD TO RETURN");
    frameBuffer.pushSprite(0, 0);
}

static void drawHuntScreen() {
    frameBuffer.fillScreen(TFT_BLACK);
    frameBuffer.fillScreen(TFT_BLACK);
    frameBuffer.setTextSize(2);
    frameBuffer.setTextColor(TFT_GREEN);
    frameBuffer.setCursor(65, 10);
    frameBuffer.print("BLE HUNT");

    frameBuffer.setTextSize(1);
    frameBuffer.setTextColor(TFT_CYAN);
    frameBuffer.setCursor(45, 34);
    frameBuffer.print("Target:");

    if (hunterTargetName[0]) {
        frameBuffer.setTextColor(TFT_WHITE);
        frameBuffer.setCursor(75, 34);
        char buf[13];
        strncpy(buf, hunterTargetName, 12);
        buf[12] = '\0';
        frameBuffer.print(buf);
    }

    frameBuffer.setTextColor(TFT_DARKGREEN);
    frameBuffer.setCursor(25, 52);
    char sm[10];
    const char* m = hunterTargetMac;
    snprintf(sm, 10, "%c%c:%c%c:%c%c:%c%c", m[9], m[10], m[12], m[13], m[15], m[16], m[0], m[1]);
    frameBuffer.print(sm);

    // Signal level indicator
    int level = (hunterTargetRssi >= -35) ? 4 : (hunterTargetRssi >= -55) ? 3 :
                (hunterTargetRssi >= -75) ? 2 : 1;
    const char* levelLabel = "";
    unsigned int levelColor;
    switch (level) {
        case 4: levelLabel = "HOT"; levelColor = TFT_RED; break;
        case 3: levelLabel = "STRONG"; levelColor = TFT_ORANGE; break;
        case 2: levelLabel = "FAIR"; levelColor = TFT_YELLOW; break;
        default: levelLabel = "WEAK"; levelColor = TFT_GREEN; break;
    }

    frameBuffer.setTextSize(2);
    frameBuffer.setTextColor(levelColor);
    frameBuffer.setCursor(15, 78);
    frameBuffer.print(levelLabel);

    // RSSI value
    frameBuffer.setTextSize(1);
    frameBuffer.setTextColor(TFT_WHITE);
    frameBuffer.setCursor(120, 78);
    frameBuffer.printf("%d dBm", hunterTargetRssi);

    // Large RSSI bar
    int bv = tailsBarValue(hunterTargetRssi);
    frameBuffer.setTextSize(2);
    frameBuffer.setTextColor(levelColor);
    frameBuffer.setCursor(15, 110);
    for (int b = 0; b < bv; b++) frameBuffer.print("#");
    for (int b = bv; b < 10; b++) frameBuffer.print("-");

    // Animated signal-wave circles
    static unsigned long hunterWaveMs = 0;
    static int wavePhase = 0;
    if (millis() - hunterWaveMs > 400) {
        hunterWaveMs = millis();
        wavePhase = (wavePhase + 1) % 4;
    }
    unsigned long fadeColors[] = { TFT_WHITE, TFT_GREEN, TFT_YELLOW, TFT_RED };
    int cx = 200, cy = 105;
    for (int r = 0; r < 4; r++) {
        int radius = 10 + r * 8 + wavePhase * 2;
        frameBuffer.drawCircle(cx, cy, radius, fadeColors[r]);
    }

    // Beep history indicator
    frameBuffer.setTextSize(1);
    frameBuffer.setTextColor(TFT_DARKGREEN);
    frameBuffer.setCursor(15, 140);
    frameBuffer.print("Signal beeps active");

    frameBuffer.setTextColor(TFT_DARKGREEN);
    frameBuffer.setCursor(55, 218);
    frameBuffer.print("HOLD TO RETURN");
    frameBuffer.pushSprite(0, 0);
}

// ======================================================
// WIFI HUNT SCREENS
// ======================================================

static void drawWifiHuntPickScreen() {
    frameBuffer.fillScreen(TFT_BLACK);
    frameBuffer.setTextSize(2);
    frameBuffer.setTextColor(TFT_GREEN);
    frameBuffer.setCursor(65, 15);
    frameBuffer.print("WIFI HUNT");

    frameBuffer.setTextSize(1);
    frameBuffer.setTextColor(TFT_CYAN);
    frameBuffer.setCursor(40, 39);
    frameBuffer.print("Pick a target AP:");

    if (cachedAPCount == 0) {
        frameBuffer.setTextColor(TFT_WHITE);
        frameBuffer.setCursor(15, 80);
        frameBuffer.print("No APs cached.");
        frameBuffer.setCursor(15, 100);
        frameBuffer.print("Run WiFi Scan first");
        frameBuffer.setCursor(15, 120);
        frameBuffer.print("to populate AP list.");
        frameBuffer.setTextColor(TFT_DARKGREEN);
        frameBuffer.setCursor(70, 218);
        frameBuffer.print("HOLD TO RETURN");
        return;
    }

    int visible = min(cachedAPCount, 6);
    int startY = 52;
    int itemH = 22;
    int highlightStart = constrain(wifiHuntPickIndex - 2, 0, max(0, cachedAPCount - visible));

    for (int i = 0; i < visible; i++) {
        int idx = highlightStart + i;
        if (idx >= cachedAPCount) break;
        int y = startY + i * itemH;
        bool sel = (idx == wifiHuntPickIndex);
        if (sel) {
            frameBuffer.fillRoundRect(8, y-2, 224, itemH+2, 4, frameBuffer.color565(30, 60, 30));
        }

        // SSID (first 10 chars)
        frameBuffer.setTextColor(sel ? TFT_GREEN : TFT_WHITE);
        frameBuffer.setCursor(25, y);
        char buf[11];
        strncpy(buf, cachedAPs[idx].ssid, 10);
        buf[10] = '\0';
        frameBuffer.print(buf);

        // RSSI
        frameBuffer.setTextColor(cachedAPs[idx].rssi >= TAILS_STRONG_RSSI ? TFT_RED : TFT_WHITE);
        frameBuffer.setCursor(132, y);
        frameBuffer.print(cachedAPs[idx].rssi);
        frameBuffer.print("dBm");

        // Channel
        frameBuffer.setTextColor(TFT_DARKGREEN);
        frameBuffer.setCursor(192, y);
        frameBuffer.print("ch");
        frameBuffer.print(cachedAPs[idx].channel);
    }

    frameBuffer.setTextColor(TFT_DARKGREEN);
    frameBuffer.setCursor(65, 218);
    frameBuffer.print("HOLD TO SELECT");
    frameBuffer.pushSprite(0, 0);
}

static void drawWifiHuntScreen() {
    frameBuffer.fillScreen(TFT_BLACK);
    frameBuffer.setTextSize(2);
    frameBuffer.setTextColor(TFT_GREEN);
    frameBuffer.setCursor(60, 10);
    frameBuffer.print("WIFI HUNT");

    frameBuffer.setTextSize(1);

    // Target SSID
    frameBuffer.setTextColor(TFT_CYAN);
    frameBuffer.setCursor(35, 34);
    frameBuffer.print("Target:");
    if (wifiHuntTargetSsid[0]) {
        frameBuffer.setTextColor(TFT_WHITE);
        frameBuffer.setCursor(75, 34);
        char buf[13];
        strncpy(buf, wifiHuntTargetSsid, 12);
        buf[12] = '\0';
        frameBuffer.print(buf);
    }

    // BSSID (short)
    frameBuffer.setTextColor(TFT_DARKGREEN);
    frameBuffer.setCursor(35, 52);
    const char* m = wifiHuntTargetBssid;
    char sm[10];
    snprintf(sm, 10, "%c%c:%c%c:%c%c:%c%c", m[9], m[10], m[12], m[13], m[15], m[16], m[0], m[1]);
    frameBuffer.print(sm);

    // Signal level
    int level = (wifiHuntTargetRssi >= -35) ? 4 : (wifiHuntTargetRssi >= -55) ? 3 :
                (wifiHuntTargetRssi >= -75) ? 2 : 1;
    const char* levelLabel = "";
    unsigned int levelColor;
    switch (level) {
        case 4: levelLabel = "HOT"; levelColor = TFT_RED; break;
        case 3: levelLabel = "STRONG"; levelColor = TFT_ORANGE; break;
        case 2: levelLabel = "FAIR"; levelColor = TFT_YELLOW; break;
        default: levelLabel = "WEAK"; levelColor = TFT_GREEN; break;
    }

    frameBuffer.setTextSize(2);
    frameBuffer.setTextColor(levelColor);
    frameBuffer.setCursor(15, 78);
    frameBuffer.print(levelLabel);

    frameBuffer.setTextSize(1);
    frameBuffer.setTextColor(TFT_WHITE);
    frameBuffer.setCursor(120, 78);
    frameBuffer.printf("%d dBm", wifiHuntTargetRssi);

    int bv = tailsBarValue(wifiHuntTargetRssi);
    frameBuffer.setTextSize(2);
    frameBuffer.setTextColor(levelColor);
    frameBuffer.setCursor(15, 110);
    for (int b = 0; b < bv; b++) frameBuffer.print("#");
    for (int b = bv; b < 10; b++) frameBuffer.print("-");

    // Animated wave
    static unsigned long wifiWaveMs = 0;
    static int wavePhase = 0;
    if (millis() - wifiWaveMs > 400) {
        wifiWaveMs = millis();
        wavePhase = (wavePhase + 1) % 4;
    }
    unsigned long fadeColors[] = { TFT_WHITE, TFT_GREEN, TFT_YELLOW, TFT_RED };
    int cx = 200, cy = 105;
    for (int r = 0; r < 4; r++) {
        int radius = 10 + r * 8 + wavePhase * 2;
        frameBuffer.drawCircle(cx, cy, radius, fadeColors[r]);
    }

    frameBuffer.setTextSize(1);
    frameBuffer.setTextColor(TFT_DARKGREEN);
    frameBuffer.setCursor(15, 140);
    frameBuffer.print("WiFi scanning...");

    frameBuffer.setTextColor(TFT_DARKGREEN);
    frameBuffer.setCursor(55, 218);
    frameBuffer.print("HOLD TO RETURN");
    frameBuffer.pushSprite(0, 0);
}

// ======================================================
// BLE CALLBACK (lightweight — only fills ring buffer)
// ======================================================

#ifndef DISABLE_BLE
class MyScanCallbacks : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice* advertisedDevice) {
        int next = (resultQueueHead + 1) % RESULT_QUEUE_SIZE;
        if (next == resultQueueTail) return;

        std::string macStr = advertisedDevice->getAddress().toString();
        strncpy(resultQueue[resultQueueHead].mac, macStr.c_str(), 17);
        resultQueue[resultQueueHead].mac[17] = '\0';

        if (advertisedDevice->haveName()) {
            std::string n = advertisedDevice->getName();
            strncpy(resultQueue[resultQueueHead].name, n.c_str(), 23);
        } else {
            strncpy(resultQueue[resultQueueHead].name, "UNKNOWN", 23);
        }
        resultQueue[resultQueueHead].name[23] = '\0';

        resultQueue[resultQueueHead].rssi = advertisedDevice->getRSSI();

        resultQueueHead = next;
    }
};

// ======================================================
// BLE INIT TASK (non-blocking with timeout)
// ======================================================

static TaskHandle_t bleInitTask = NULL;
static volatile bool bleInitDone = false;
static volatile bool bleInitSuccess = false;
static unsigned long bleInitStartMs = 0;

void bleInitTaskFunc(void *pvParameters) {
    delay(10);
    NimBLEDevice::init("");
    pBLEScan = NimBLEDevice::getScan();
    pBLEScan->setScanCallbacks(new MyScanCallbacks());
    pBLEScan->setActiveScan(true);
    bleInitSuccess = true;
    bleInitDone = true;
    vTaskDelete(NULL);
}
#endif

// ======================================================
// HELPERS
// ======================================================

bool isDeviceKnown(const char* mac) {
    for (int i = 0; i < knownDeviceCount; i++) {
        if (strcmp(knownDevices[i], mac) == 0) return true;
    }
    return false;
}

int findDeviceIndex(const char* mac) {
    for (int i = 0; i < deviceCount; i++) {
        if (strcmp(devices[i].mac, mac) == 0) return i;
    }
    return -1;
}

// ======================================================
// SD LOG ROTATION
// ======================================================

void checkLogRotation(const char* path) {
    File f = SD.open(path, FILE_READ);
    if (!f) return;
    bool tooBig = (f.size() > MAX_LOG_SIZE);
    f.close();
    if (tooBig) {
        SD.remove(path);
    }
}

void saveKnownDevice(const char* mac) {
    if (!sdReady || knownDeviceCount >= MAX_KNOWN_DEVICES) return;
    File file = SD.open("/known_devices.txt", FILE_APPEND);
    if (!file) return;
    file.println(mac);
    file.close();
}

void loadKnownDevices() {
    if (!sdReady) return;
    File file = SD.open("/known_devices.txt");
    if (!file) {
        Serial.println("NO DATABASE FOUND");
        return;
    }
    while (file.available() && knownDeviceCount < MAX_KNOWN_DEVICES) {
        String mac = file.readStringUntil('\n');
        mac.trim();
        if (mac.length() > 0) {
            strncpy(knownDevices[knownDeviceCount], mac.c_str(), 17);
            knownDevices[knownDeviceCount][17] = '\0';
            knownDeviceCount++;
        }
    }
    file.close();
    Serial.printf("DATABASE LOADED: %d entries\n", knownDeviceCount);
}

// ======================================================
// LOG DETECTION
// ======================================================

void logDetection(const DeviceInfo& dev) {
    if (!sdReady) return;

    checkLogRotation("/logs.txt");
    File file = SD.open("/logs.txt", FILE_APPEND);
    if (!file) return;

    const char* modeText = (currentMode == BLE_MODE) ? "BLE" : "WIFI";

    file.print("[");
    file.print(modeText);
    file.print("] ");
    file.print(millis());
    file.print(" | ");
    file.print(dev.mac);
    file.print(" | ");
    file.print(dev.name);
    file.print(" | RSSI:");
    file.println(dev.rssi);
    totalLogs++;
    file.close();

    if (dev.rssi > RSSI_CRITICAL) {
        checkLogRotation("/threats.txt");
        File threat = SD.open("/threats.txt", FILE_APPEND);
        if (threat) {
            threat.print("[HIGH] ");
            threat.print(dev.mac);
            threat.print(" | ");
            threat.print(dev.name);
            threat.print(" | RSSI:");
            threat.println(dev.rssi);
            threat.close();
        }
    }
}

// ======================================================
// ADD OR UPDATE DEVICE
// ======================================================

int addOrUpdateDevice(const char* mac, const char* name, int8_t rssi) {
    int idx = findDeviceIndex(mac);
    if (idx >= 0) {
        devices[idx].rssi = rssi;
        devices[idx].lastSeen = millis();
        return idx;
    }

    bool known = isDeviceKnown(mac);
    bool isNewDev = !known;

    if (isNewDev) {
        if (knownDeviceCount < MAX_KNOWN_DEVICES) {
            strncpy(knownDevices[knownDeviceCount], mac, 17);
            knownDevices[knownDeviceCount][17] = '\0';
            knownDeviceCount++;
        }
        saveKnownDevice(mac);
        newDeviceDetected = true;
        alertTimer = millis();
    }

    int slot = -1;

    if (deviceCount < MAX_DEVICES) {
        slot = deviceCount;
        deviceCount++;
    } else {
        // FIFO eviction — replace oldest
        unsigned long oldestTime = devices[0].lastSeen;
        slot = 0;
        for (int i = 1; i < MAX_DEVICES; i++) {
            if (devices[i].lastSeen < oldestTime) {
                oldestTime = devices[i].lastSeen;
                slot = i;
            }
        }
    }

    strncpy(devices[slot].mac, mac, 17);
    devices[slot].mac[17] = '\0';
    strncpy(devices[slot].name, name, 23);
    devices[slot].name[23] = '\0';
    devices[slot].rssi = rssi;
    devices[slot].isNew = isNewDev;
    devices[slot].firstSeen = millis();
    devices[slot].lastSeen = millis();

    if (isNewDev) {
        logDetection(devices[slot]);
    }

    return slot;
}

// ======================================================
// PROCESS QUEUED BLE RESULTS
// ======================================================

#ifndef DISABLE_BLE
void processBLEResults() {
    while (resultQueueTail != resultQueueHead) {
        ScanResult& r = resultQueue[resultQueueTail];
        addOrUpdateDevice(r.mac, r.name, r.rssi);
        resultQueueTail = (resultQueueTail + 1) % RESULT_QUEUE_SIZE;
    }
}
#endif

// ======================================================
// UPDATE ACTIVE TARGET
// ======================================================

void updateTargetTracking() {
    activeTargetIndex = -1;
    int strongest = RSSI_FLOOR;

    for (int i = 0; i < deviceCount; i++) {
        if (millis() - devices[i].lastSeen > DEVICE_TIMEOUT_MS) continue;
        if (devices[i].rssi > strongest) {
            strongest = devices[i].rssi;
            activeTargetIndex = i;
        }
    }
}

// ======================================================
// RADAR DRAWING
// ======================================================

void drawRadarBg() {
    frameBuffer.fillScreen(TFT_BLACK);
    const int cx = 120, cy = 120;
    frameBuffer.drawCircle(cx, cy, 100, TFT_DARKGREEN);
    frameBuffer.drawCircle(cx, cy, 75, TFT_DARKGREEN);
    frameBuffer.drawCircle(cx, cy, 50, TFT_DARKGREEN);
    frameBuffer.drawCircle(cx, cy, 25, TFT_DARKGREEN);
    frameBuffer.drawLine(cx, 20, cx, 220, TFT_DARKGREEN);
    frameBuffer.drawLine(20, cy, 240 - 20, cy, TFT_DARKGREEN);
}

void drawSweep() {
    const int cx = 120, cy = 120;
    float rad = sweepAngle * 0.0174533f;
    int x = cx + (int)(cosf(rad) * 95.0f);
    int y = cy + (int)(sinf(rad) * 95.0f);
    frameBuffer.drawLine(cx, cy, x, y, TFT_GREEN);
    sweepAngle += SWEEP_STEP;
    if (sweepAngle >= 360) sweepAngle = 0;
}

void drawDevices() {
    for (int i = 0; i < deviceCount; i++) {
        const DeviceInfo& d = devices[i];

        if (millis() - d.lastSeen > DEVICE_TIMEOUT_MS) continue;

        int radius = map(d.rssi, RSSI_FLOOR, RSSI_CEIL, 90, 20);
        radius = constrain(radius, 20, 90);

        uint32_t hash = 0;
        for (int j = 0; d.mac[j]; j++) {
            hash = (hash * 31) + (unsigned char)d.mac[j];
        }
        int angle = hash % 360;
        float rad = angle * 0.0174533f;
        int x = 120 + (int)(cosf(rad) * radius);
        int y = 120 + (int)(sinf(rad) * radius);

        uint16_t colour = d.isNew ? TFT_CYAN : TFT_GREEN;
        if (d.rssi > RSSI_STRONG)   colour = TFT_YELLOW;
        if (d.rssi > RSSI_CRITICAL) colour = TFT_RED;
        if (i == activeTargetIndex) colour = TFT_MAGENTA;

        frameBuffer.fillCircle(x, y, 2, colour);
        frameBuffer.drawCircle(x, y, 4, colour);

        if (i == activeTargetIndex) {
            frameBuffer.drawCircle(x, y, 6 + pulseSize, TFT_MAGENTA);
            frameBuffer.drawCircle(x, y, 10 + pulseSize, TFT_MAGENTA);
        }

        if (d.rssi > RSSI_HIGH_RISK || i == activeTargetIndex) {
            frameBuffer.setTextSize(1);
            frameBuffer.setTextColor(colour);
            frameBuffer.setCursor(x + 8, y - 5);
            if (strcmp(d.name, "UNKNOWN") != 0) {
                char buf[9];
                strncpy(buf, d.name, 8);
                buf[8] = '\0';
                frameBuffer.print(buf);
            } else {
                frameBuffer.print("DEVICE");
            }
        }
    }
}

// ======================================================
// UI
// ======================================================

void drawUI() {
    frameBuffer.setTextColor(TFT_GREEN);
    frameBuffer.setTextSize(2);
    frameBuffer.setCursor(65, 15);
    frameBuffer.print(currentMode == BLE_MODE ? "BLE MODE" : "WIFI MODE");

    if (activeTargetIndex >= 0 && activeTargetIndex < deviceCount) {
        const DeviceInfo& t = devices[activeTargetIndex];

        frameBuffer.setTextSize(1);
        frameBuffer.setTextColor(TFT_MAGENTA);
        frameBuffer.setCursor(55, 38);
        frameBuffer.print("TARGET LOCK");

        frameBuffer.setCursor(45, 50);
        if (strcmp(t.name, "UNKNOWN") != 0) {
            char buf[13];
            strncpy(buf, t.name, 12);
            buf[12] = '\0';
            frameBuffer.print(buf);
        } else {
            frameBuffer.print("UNKNOWN DEVICE");
        }

        frameBuffer.setCursor(90, 62);
        frameBuffer.print(t.rssi);
        frameBuffer.print(" dBm");

        const char* vendor = lookupVendor(t.mac);
        if (vendor) {
            frameBuffer.setCursor(20, 74);
            frameBuffer.setTextColor(TFT_CYAN);
            frameBuffer.print(vendor);
        }
    }

    frameBuffer.setTextSize(1);
    frameBuffer.setTextColor(TFT_GREEN);
    frameBuffer.setCursor(70, 180);
    frameBuffer.printf("LOGS %d", totalLogs);

    frameBuffer.setCursor(70, 200);
    frameBuffer.printf("LIVE %d", deviceCount);

    frameBuffer.setCursor(70, 220);
    frameBuffer.printf("KNOWN %d", knownDeviceCount);

    frameBuffer.setCursor(150, 220);
    frameBuffer.print(currentMode == BLE_MODE ? "WIFI>" : "BLE>");

    if (!sdReady) {
        frameBuffer.setTextColor(TFT_RED);
        frameBuffer.setCursor(5, 5);
        frameBuffer.setTextSize(1);
        frameBuffer.print("NO SD");
    }

    if (newDeviceDetected && millis() - alertTimer < 3000) {
        frameBuffer.fillRoundRect(45, 2, 150, 20, 6, TFT_RED);
        frameBuffer.setTextColor(TFT_WHITE);
        frameBuffer.setCursor(78, 5);
        frameBuffer.setTextSize(1);
        frameBuffer.print("NEW DEVICE");
    } else {
        newDeviceDetected = false;
    }
}

// ======================================================
// WIFI AP LIST VIEW
// ======================================================

void drawWiFiList() {
    frameBuffer.fillScreen(TFT_BLACK);

    int count = cachedAPCount;
    if (count == 0) {
        frameBuffer.setTextColor(TFT_WHITE);
        frameBuffer.setTextSize(1);
        frameBuffer.setCursor(20, 110);
        frameBuffer.print("No APs found yet...");
        return;
    }

    // Header
    frameBuffer.setTextColor(TFT_CYAN);
    frameBuffer.setTextSize(1);
    frameBuffer.setCursor(20, 4);
    frameBuffer.printf("WiFi APs (%d)", count);
    frameBuffer.setTextColor(TFT_DARKGREEN);
    frameBuffer.setCursor(155, 4);
    frameBuffer.printf("RSSI CH");

    frameBuffer.drawFastHLine(0, 15, 240, TFT_DARKGREEN);

    // Clamp scroll offset
    int maxOffset = max(0, count - 8);
    if (wifiScrollOffset > maxOffset) wifiScrollOffset = maxOffset;

    int y = 20;
    int end = min(count, wifiScrollOffset + 8);
    for (int i = wifiScrollOffset; i < end; i++) {
        const CachedAP& ap = cachedAPs[i];

        // RSSI bar
        int barLen = constrain(map(ap.rssi, -100, -30, 0, 50), 0, 50);
        uint16_t barColor = TFT_GREEN;
        if (ap.rssi > -60) barColor = TFT_YELLOW;
        if (ap.rssi > -45) barColor = TFT_RED;
        frameBuffer.fillRect(2, y, barLen, 6, barColor);

        // RSSI value
        frameBuffer.setTextColor(TFT_WHITE);
        frameBuffer.setCursor(56, y - 2);
        frameBuffer.printf("%3d", ap.rssi);
        frameBuffer.print("dBm");

        // Channel
        frameBuffer.setTextColor(TFT_GREENYELLOW);
        frameBuffer.setCursor(118, y - 2);
        if (ap.channel > 0) frameBuffer.printf(" %2d", ap.channel);

        // SSID (truncate to fit)
        frameBuffer.setTextColor(TFT_WHITE);
        frameBuffer.setTextSize(1);
        char ssidBuf[13];
        strncpy(ssidBuf, ap.ssid, 12);
        ssidBuf[12] = '\0';
        if (ssidBuf[0] == '\0') strcpy(ssidBuf, "*HIDDEN*");
        frameBuffer.setCursor(138, y - 2);
        frameBuffer.print(ssidBuf);

        // BSSID on second line
        frameBuffer.setTextColor(TFT_DARKGREY);
        frameBuffer.setTextSize(1);
        frameBuffer.setCursor(56, y + 8);
        frameBuffer.print(ap.bssid);

        y += 26;
    }

    // Scroll indicator
    if (maxOffset > 0) {
        frameBuffer.setTextColor(TFT_GREEN);
        frameBuffer.setTextSize(1);
        frameBuffer.setCursor(70, 228);
        frameBuffer.printf("TAP: %d/%d", wifiScrollOffset + 1, count);
    }
}

// ======================================================
// GEIGER AUDIO
// ======================================================

void geigerSound() {
    if (activeTargetIndex < 0 || activeTargetIndex >= deviceCount) return;

    int rssi = devices[activeTargetIndex].rssi;
    int interval = map(rssi, RSSI_FLOOR, RSSI_CEIL, 1200, 40);
    int pitch    = map(rssi, RSSI_FLOOR, RSSI_CEIL, 1200, 4000);

    if (millis() - beepTimer > (unsigned long)interval) {
        tone(BUZZER_PIN, pitch, 20);
        beepTimer = millis();
    }
}

// ======================================================
// BLE SCAN (short duration to minimise AP disruption)
// ======================================================

#ifndef DISABLE_BLE
// Async BLE scan state machine
static bool bleScanBusy = false;

void startBLEScan() {
    if (bleScanBusy) return;
    bleScanBusy = true;
    pBLEScan->start(300, false, true);
}

void processBLEScan() {
    if (pBLEScan->isScanning()) return;  // still in progress
    processBLEResults();
    pBLEScan->clearResults();
    bleScanBusy = false;
}
#endif

// ======================================================
// WIFI SCAN (async — non-blocking, preserves AP link)
// ======================================================

int wifiScanState = 0; // 0=idle, 1=bootstrapping, 2=in-progress

void startWiFiScan() {
    if (wifiScanState != 0) return;
    // Kick off async scan
    WiFi.scanNetworks(true, true);
    wifiScanState = 1;
}

void processWiFiScan() {
    int n = WiFi.scanComplete();
    if (n == -1) {
        wifiScanState = 2; // still in progress
        return;
    }
    if (n == -2) {
        wifiScanState = 0; // not started (shouldn't happen)
        return;
    }

    wifiScanState = 0;
    for (int i = 0; i < n; i++) {
        String ssid  = WiFi.SSID(i);
        String bssid = WiFi.BSSIDstr(i);
        int8_t rssi  = WiFi.RSSI(i);

        char mac[18], name[24];
        strncpy(mac, bssid.c_str(), 17);
        mac[17] = '\0';
        strncpy(name, ssid.c_str(), 23);
        name[23] = '\0';

        addOrUpdateDevice(mac, name, rssi);

        // Cache AP for WiFi Hunt mode
        if (cachedAPCount < MAX_CACHED_APS) {
            int ci = -1;
            for (int j = 0; j < cachedAPCount; j++) {
                if (strcmp(cachedAPs[j].bssid, mac) == 0) { ci = j; break; }
            }
            if (ci < 0) {
                ci = cachedAPCount;
                cachedAPCount++;
                strncpy(cachedAPs[ci].bssid, mac, 17);
                cachedAPs[ci].bssid[17] = '\0';
            }
            strncpy(cachedAPs[ci].ssid, name, 23);
            cachedAPs[ci].ssid[23] = '\0';
            cachedAPs[ci].rssi = rssi;
            cachedAPs[ci].channel = WiFi.channel(i);
            cachedAPs[ci].lastSeen = millis();
        }
    }
    WiFi.scanDelete();
}


// ======================================================
// CLEANUP STALE DEVICES
// ======================================================

void cleanupDevices() {
    for (int i = deviceCount - 1; i >= 0; i--) {
        if (millis() - devices[i].lastSeen > CLEANUP_TIMEOUT_MS) {
            int moveCount = deviceCount - i - 1;
            if (moveCount > 0) {
                memmove(&devices[i], &devices[i + 1], moveCount * sizeof(DeviceInfo));
            }
            deviceCount--;
        }
    }
}

// ======================================================
// STATE FLAGS (file-scope so touch handler and loop can share)
// ======================================================

static bool firstMenuDraw = true;
#ifndef DISABLE_BLE
static bool bleInitted = false;
#endif
static bool wifiInitted = false;
static bool webUIActive = false;
static unsigned long apStartTime = 0;
static bool apClientEverConnected = false;
static AppState lastAppState = APP_MENU;
#ifndef DISABLE_BLE
static bool bleScanEntered = false;
#endif
static bool wifiScanEntered = false;
static bool configDrawn = false;
static bool aboutDrawn = false;
static unsigned long lastDrawTime = 0;
// ======================================================
// TOUCH HANDLER (CHSC6X: INT pin LOW = pressed, HIGH = released)

static bool touching = false;
static unsigned long touchStartMs = 0;

void handleTouch() {
    // IRQ HIGH + not tracking = no activity, skip fast
    if (digitalRead(TOUCH_IRQ) == HIGH && !touching) return;
    if (millis() - lastTouchMs < TOUCH_DEBOUNCE_MS) return;

    // Read CHSC6X I2C to get actual touch state and acknowledge INT
    Wire.requestFrom(0x2E, 5);
    uint8_t buf[5] = {0};
    for (int i = 0; i < 5 && Wire.available(); i++) buf[i] = Wire.read();
    bool pressed = (buf[0] == 0x01); // byte 0 = touch status

    lastTouchMs = millis();

    if (pressed && !touching) {
        touching = true;
        touchStartMs = millis();
    } else if (!pressed && touching) {
        touching = false;
        unsigned long duration = millis() - touchStartMs;

        if (duration < 400) {
            // --- SHORT TAP ---
            if (millis() - lastEasterTapMs > 5000) { easterTapCount = 0; configTapCount = 0; }
            lastEasterTapMs = millis();
            tone(BUZZER_PIN, 3000, 15);
            if (appState == APP_CONFIG) {
                configTapCount++;
                if (configTapCount >= 7) {
                    configTapCount = 0;
                    frameBuffer.fillScreen(TFT_BLACK);
                    frameBuffer.pushImage(20, 20, SQUIRREL_EGG_WIDTH, SQUIRREL_EGG_HEIGHT, squirrel_egg);
                    frameBuffer.setTextSize(2);
                    frameBuffer.setTextColor(TFT_CYAN);
                    frameBuffer.setCursor(40, 215);
                    frameBuffer.print("SQUIRREL!");
                    frameBuffer.pushSprite(0, 0);
                    delay(5000);
                    return;
                }
                return;
            }
#ifndef DISABLE_BLE
            if (appState == APP_HUNTER && hunterPicking) {
                int lc = 0;
                for (int i = 0; i < tailSlotCount; i++)
                    if (tailSlots[i].seenCount > 0) lc++;
                if (lc > 0) {
                    hunterPickIndex = (hunterPickIndex + 1) % lc;
                    drawHunterPickScreen();
                }
                return;
            }
#endif
            if (appState == APP_WIFI_HUNT && wifiHuntPicking) {
                if (cachedAPCount > 0) {
                    wifiHuntPickIndex = (wifiHuntPickIndex + 1) % cachedAPCount;
                    drawWifiHuntPickScreen();
                }
                return;
            }
            easterTapCount++;
            if (easterTapCount >= EASTER_EGG_TAPS) {
                easterTapCount = 0;
                drawEasterEgg();
                delay(5000);
                if (appState == APP_MENU) firstMenuDraw = true;
                return;
            }
            if (appState == APP_MENU) {
                menuIndex = (menuIndex + 1) % menuCount;
                firstMenuDraw = true;
            } else if (appState == APP_BLE_SCAN) {
                if (deviceCount > 0)
                    activeTargetIndex = (activeTargetIndex + 1) % deviceCount;
            } else if (appState == APP_WIFI_SCAN) {
                wifiScrollOffset++;
                if (wifiScrollOffset >= cachedAPCount) wifiScrollOffset = 0;
            } else if (appState == APP_PRESENCE_RADAR) {
                if (presenceRadar.connectionState() == NODE_CONNECTED) {
                    if (presenceRadar.eventLogVisible()) {
                        presenceRadar.scrollEventLog(1);
                    } else if (presenceRadar.nodeHealthVisible()) {
                        presenceRadar.requestEventLog();
                    } else {
                        presenceRadar.requestNodeHealth();
                    }
                }
            }
        } else {
            // --- LONG HOLD ---
            easterTapCount = 0;
            configTapCount = 0;
            tone(BUZZER_PIN, 1500, 50);
            if (appState == APP_MENU) {
                switch (menuIndex) {
                    case 0: appState = APP_BLE_SCAN; currentMode = BLE_MODE; break;
                    case 1: appState = APP_WIFI_SCAN; currentMode = WIFI_MODE; break;
                    case 2: appState = APP_CONFIG; break;
                    case 3: appState = APP_DEAUTH; break;
                    case 4: appState = APP_TRIPWIRE; break;
                    case 5: appState = APP_HUNTER; break;
                    case 6: appState = APP_WIFI_HUNT; break;
                    case 7: appState = APP_EVIL_TWIN; break;
                    case 8: appState = APP_MAC_RAND; break;
                    case 9: appState = APP_PRESENCE_RADAR; break;
                    case 10: appState = APP_ABOUT; break;
                }
                frameBuffer.fillScreen(TFT_BLACK);
            }
#ifndef DISABLE_BLE
            else if (appState == APP_HUNTER && hunterPicking) {
                // Select target: find the one at current pick index
                int lc = 0;
                struct { int idx; } list[HUNTER_PICK_COUNT];
                for (int i = 0; i < tailSlotCount && lc < HUNTER_PICK_COUNT; i++) {
                    if (tailSlots[i].seenCount == 0) continue;
                    int r = getTailRssi(tailSlots[i].mac);
                    int pos = lc;
                    while (pos > 0 && (tailSlots[i].seenCount > tailSlots[list[pos-1].idx].seenCount ||
                           (tailSlots[i].seenCount == tailSlots[list[pos-1].idx].seenCount && r > getTailRssi(tailSlots[list[pos-1].idx].mac))))
                        pos--;
                    if (pos < HUNTER_PICK_COUNT) {
                        if (lc < HUNTER_PICK_COUNT) lc++;
                        for (int j = lc-1; j > pos; j--) list[j] = list[j-1];
                        list[pos].idx = i;
                    }
                }
                if (lc > 0 && hunterPickIndex < lc) {
                    int sel = list[hunterPickIndex].idx;
                    strncpy(hunterTargetMac, tailSlots[sel].mac, 17);
                    hunterTargetMac[17] = '\0';
                    const char* nm = getTailName(tailSlots[sel].mac);
                    if (nm && nm[0]) {
                        strncpy(hunterTargetName, nm, 23);
                        hunterTargetName[23] = '\0';
                    } else {
                        hunterTargetName[0] = '\0';
                    }
                    hunterHunting = true;
                    hunterPicking = false;
                    deviceCount = 0;
                    drawHuntScreen();
                }
            }
#endif
            else if (appState == APP_WIFI_HUNT && wifiHuntPicking) {
                if (cachedAPCount > 0 && wifiHuntPickIndex < cachedAPCount) {
                    strncpy(wifiHuntTargetBssid, cachedAPs[wifiHuntPickIndex].bssid, 17);
                    wifiHuntTargetBssid[17] = '\0';
                    strncpy(wifiHuntTargetSsid, cachedAPs[wifiHuntPickIndex].ssid, 23);
                    wifiHuntTargetSsid[23] = '\0';
                    wifiHuntTargetRssi = cachedAPs[wifiHuntPickIndex].rssi;
                    wifiHuntTargetChannel = cachedAPs[wifiHuntPickIndex].channel;
                    parseMacBytes(wifiHuntTargetBssid, wifiHuntTargetBytes);
                    wifiHuntHunting = true;
                    wifiHuntPicking = false;
                    wifiHuntSniffing = false;
                    wifiHuntPacketTimer = millis();
                    wifiHuntLastSignalMs = millis();
                    wifiHuntPrevLevel = 0;
                    deviceCount = 0;
                    drawWifiHuntScreen();
                }
            } else {
                appState = APP_MENU;
                menuIndex = 0;
                frameBuffer.fillScreen(TFT_BLACK);
            }
        }
    }
}

// ======================================================
// MENU / ABOUT DRAWING
// ======================================================

// ======================================================
// EASTER EGG
// ======================================================

void drawEasterEgg() {
    frameBuffer.fillScreen(TFT_BLACK);
    for (int y = 0; y < 240; y += 4) {
        frameBuffer.fillRect(0, y, 240, 2, frameBuffer.color565(y * 6 % 256, y * 3 % 256, 255 - y));
    }
    frameBuffer.fillCircle(120, 100, 50, TFT_BLACK);
    frameBuffer.fillCircle(120, 100, 48, frameBuffer.color565(255, 200, 0));
    frameBuffer.fillCircle(110, 90, 6, TFT_BLACK);
    frameBuffer.fillCircle(130, 90, 6, TFT_BLACK);
    frameBuffer.fillCircle(120, 105, 4, TFT_BLACK);
    frameBuffer.fillCircle(120, 110, 8, frameBuffer.color565(200, 0, 0));
    frameBuffer.setTextSize(2);
    frameBuffer.setTextColor(TFT_CYAN);
    frameBuffer.setCursor(55, 20);
    frameBuffer.print("EASTER EGG!");
    frameBuffer.setTextSize(1);
    frameBuffer.setTextColor(TFT_WHITE);
    frameBuffer.setCursor(55, 180);
    frameBuffer.print("10 taps, nice!");
    frameBuffer.setCursor(45, 200);
    frameBuffer.print("now hold to return");
    frameBuffer.pushSprite(0, 0);
}

void drawMenu() {
    frameBuffer.fillScreen(TFT_BLACK);
    frameBuffer.setTextSize(2);
    frameBuffer.setTextColor(TFT_GREEN);
    frameBuffer.setCursor(65, 16);
    frameBuffer.print("TRIPWIRE");

    #define MENU_VISIBLE 4
    int start = constrain(menuIndex - 1, 0, max(0, menuCount - MENU_VISIBLE));

    frameBuffer.setTextSize(1);
    for (int i = 0; i < MENU_VISIBLE; i++) {
        int idx = start + i;
        if (idx >= menuCount) break;
        int y = 62 + i * 36;
        if (idx == menuIndex) {
            frameBuffer.fillRoundRect(50, y - 4, 140, 22, 6, TFT_DARKGREEN);
            frameBuffer.setTextColor(TFT_BLACK);
            frameBuffer.setCursor(62, y);
            frameBuffer.print(menuItems[idx]);
        } else {
            frameBuffer.setTextColor(TFT_GREEN);
            frameBuffer.setCursor(62, y);
            frameBuffer.print(menuItems[idx]);
        }
    }

    frameBuffer.setTextColor(TFT_DARKGREEN);
    frameBuffer.setCursor(55, 200);
    frameBuffer.setTextSize(1);
    frameBuffer.print("TAP: NAV   HOLD: SELECT");
    frameBuffer.pushSprite(0, 0);
}

void drawAbout() {
    frameBuffer.fillScreen(TFT_BLACK);
    frameBuffer.setTextColor(TFT_GREEN);
    frameBuffer.setTextSize(2);
    frameBuffer.setCursor(55, 20);
    frameBuffer.print("DIGITAL              TRIPWIRE");
    frameBuffer.setTextSize(1);
    frameBuffer.setCursor(25, 75);
    frameBuffer.print("BLE/WiFi Radar Scanner");
    frameBuffer.setCursor(25, 95);
    frameBuffer.print("XIAO ESP32C5 WITH SEEED STUDIO             ROUND DISPLAY");
    frameBuffer.setCursor(25, 125);
    frameBuffer.printf("Devices: %d", deviceCount);
    frameBuffer.setCursor(25, 145);
    frameBuffer.printf("Known: %d", knownDeviceCount);
    frameBuffer.setCursor(25, 165);
    frameBuffer.printf("Logs: %d", totalLogs);
    frameBuffer.setTextColor(TFT_DARKGREEN);
    frameBuffer.setCursor(65, 218);
    frameBuffer.print("NOTORIOUS SQUIRREL");
    frameBuffer.pushSprite(0, 0);
}

// ======================================================
// DEAUTH DETECTOR SCREEN
// ======================================================

void drawDeauthScreen() {
    frameBuffer.fillScreen(TFT_BLACK);
    frameBuffer.setTextColor(TFT_RED);
    frameBuffer.setTextSize(1.75);
    frameBuffer.setCursor(65, 30);
    frameBuffer.print("DEAUTH DETECTOR");
    frameBuffer.setTextSize(1);
    frameBuffer.setTextColor(TFT_WHITE);
    frameBuffer.setCursor(30, 75);
    frameBuffer.print("Monitoring WiFi...");
    frameBuffer.setTextColor(TFT_CYAN);
    frameBuffer.setCursor(30, 100);
    frameBuffer.print("Deauths:");
    frameBuffer.setTextColor(TFT_YELLOW);
    frameBuffer.setCursor(100, 100);
    frameBuffer.print("0");
    frameBuffer.setTextColor(TFT_WHITE);
    frameBuffer.setCursor(30, 125);
    frameBuffer.print("Last source:");
    frameBuffer.setTextColor(TFT_ORANGE);
    frameBuffer.setCursor(30, 145);
    frameBuffer.print("none");
    frameBuffer.setTextColor(TFT_DARKGREEN);
    frameBuffer.setCursor(75, 218);
    frameBuffer.print("HOLD TO RETURN");
    frameBuffer.pushSprite(0, 0);
}

// ======================================================
// SETUP
// ======================================================

void setup() {
    Serial.begin(115200);
    Serial.println("[BOOT] Starting...");

    pinMode(TFT_BL, OUTPUT);
    digitalWrite(TFT_BL, HIGH);

    pinMode(BUZZER_PIN, OUTPUT);

    Wire.begin(TOUCH_SDA, TOUCH_SCL);
    pinMode(TOUCH_IRQ, INPUT_PULLUP); // CHSC6X INT: LOW = pressed, HIGH = released

    tft.init();
    tft.setRotation(0);

    // Boot screen (draw directly to TFT — sprite doesn't exist yet)
    tft.fillScreen(TFT_BLACK);
    tft.pushImage(0, 0, 240, 240, notorious_squirrel_boot_240x240_TRUE24);
    delay(2000);

    // Create sprite framebuffer for double-buffered rendering
    tft.setAttribute(PSRAM_ENABLE, 1);
    frameBuffer.setColorDepth(16);
    if (!frameBuffer.createSprite(240, 240)) {
        Serial.println("[BOOT] SPRITE FAILED!");
        while (1) { delay(100); } // halt
    }

    // SD card
    sdReady = SD.begin(SD_CS);
    if (!sdReady) {
        Serial.println("[BOOT] SD FAILED");
    } else {
        Serial.println("[BOOT] SD OK");
        loadKnownDevices();
        int ouiCount = loadOuiFromSD();
        Serial.printf("[BOOT] OUI entries: %d\n", ouiCount);
    }

    Serial.println("[BOOT] Setup complete (waiting for deferred init)");
}



// ======================================================
// LOOP
// ======================================================

void loop() {
    unsigned long now = millis();

    // --- Touch ---
    handleTouch();

    // ========================================================
    // STATE TRANSITION: cleanup previous state, reset per-state flags
    // ========================================================
    if (appState != lastAppState) {
        if (lastAppState == APP_CONFIG && webUIActive) {
            stopWebUI();
            webUIActive = false;
        }
        if (lastAppState == APP_DEAUTH && deauthActive) {
            esp_wifi_set_promiscuous(false);
            esp_wifi_stop();
            deauthActive = false;
        }
        if (lastAppState == APP_WIFI_HUNT && wifiHuntSniffing) {
            wifiHuntSniffing = false;
        }
        if (lastAppState == APP_PRESENCE_RADAR) {
            presenceRadar.cleanup();
        }
        pentestCleanup();
        tailsDrawn = false;
        hunterDrawn = false;
        wifiHuntDrawn = false;
        wifiInitted = false;
        wifiScanState = 0;
        wifiScanEntered = false;
        wifiScrollOffset = 0;
        configDrawn = false;
        aboutDrawn = false;
        deauthDrawn = false;
#ifndef DISABLE_BLE
        bleScanBusy = false;
        bleScanEntered = false;
        bleInitted = false;
        bleInitDone = false;
        if (bleInitTask != NULL) {
            vTaskDelete(bleInitTask);
            bleInitTask = NULL;
        }
#endif
        lastAppState = appState;
        firstMenuDraw = true;
    }

    // ========================================================
    // STATE MACHINE DISPATCH
    // ========================================================

    switch (appState) {

        // ------------------------------------------------
        // MAIN MENU
        // ------------------------------------------------
        case APP_MENU:
            if (firstMenuDraw) {
                drawMenu();
                firstMenuDraw = false;
            }
            break;

        // ------------------------------------------------
        // BLE SCAN MODE
        // ------------------------------------------------
        case APP_BLE_SCAN:
#ifndef DISABLE_BLE
            if (!bleInitted) {
                bleInitted = true;
                frameBuffer.fillScreen(TFT_BLACK);
                frameBuffer.setTextColor(TFT_GREEN);
                frameBuffer.setTextSize(2);
                frameBuffer.setCursor(40, 100);
                frameBuffer.print("INIT BLE...");
                frameBuffer.setTextSize(1);
                frameBuffer.setCursor(40, 130);
                frameBuffer.print("(this may take a moment)");
                frameBuffer.setTextColor(TFT_DARKGREEN);
                frameBuffer.setCursor(40, 218);
                frameBuffer.print("HOLD TO CANCEL");
                frameBuffer.pushSprite(0, 0);
                bleInitDone = false;
                bleInitSuccess = false;
                bleInitStartMs = millis();
                xTaskCreate(bleInitTaskFunc, "bleInit", 4096, NULL, 1, &bleInitTask);
            }
            if (!bleInitDone) {
                if (millis() - bleInitStartMs > 10000) {
                    if (bleInitTask != NULL) {
                        vTaskDelete(bleInitTask);
                        bleInitTask = NULL;
                    }
                    bleInitted = false;
                    appState = APP_MENU;
                    frameBuffer.fillScreen(TFT_BLACK);
                    frameBuffer.setTextColor(TFT_RED);
                    frameBuffer.setTextSize(2);
                    frameBuffer.setCursor(15, 100);
                    frameBuffer.print("BLE INIT FAILED");
                    frameBuffer.pushSprite(0, 0);
                    delay(1500);
                }
                break;
            }
            if (!bleScanEntered) {
                bleScanEntered = true;
                startBLEScan();
            }
            processBLEScan();
            if (!bleScanBusy && !scanningPaused && now - lastScan > SCAN_INTERVAL_MS) {
                startBLEScan();
                lastScan = now;
            }
            updateTargetTracking();
            if (now - targetPulseTimer > PULSE_INTERVAL_MS) {
                pulseSize = (pulseSize + 1) % 7;
                targetPulseTimer = now;
            }
            geigerSound();
            cleanupDevices();
            if (now - lastDrawTime > DRAW_INTERVAL_MS) {
                drawRadarBg();
                drawDevices();
                drawUI();
                drawSweep();
                frameBuffer.pushSprite(0, 0);
                lastDrawTime = now;
            }
#else
            frameBuffer.fillScreen(TFT_BLACK);
            frameBuffer.setTextColor(TFT_RED);
            frameBuffer.setTextSize(2);
            frameBuffer.setCursor(20, 100);
            frameBuffer.print("BLE NOT AVAILABLE");
            frameBuffer.setTextSize(1);
            frameBuffer.setTextColor(TFT_WHITE);
            frameBuffer.setCursor(15, 140);
            frameBuffer.print("ESP32-C5 lacks NimBLE");
            frameBuffer.setTextColor(TFT_DARKGREEN);
            frameBuffer.setCursor(40, 218);
            frameBuffer.print("HOLD TO RETURN");
            frameBuffer.pushSprite(0, 0);
#endif
            break;

        // ------------------------------------------------
        // WIFI SCAN MODE
        // ------------------------------------------------
        case APP_WIFI_SCAN:
            if (!wifiInitted) {
                wifiInitted = true;
                frameBuffer.fillScreen(TFT_BLACK);
                frameBuffer.setTextColor(TFT_GREEN);
                frameBuffer.setTextSize(2);
                frameBuffer.setCursor(40, 100);
                frameBuffer.print("INIT WiFi...");
                frameBuffer.pushSprite(0, 0);
                WiFi.mode(WIFI_STA);
                WiFi.disconnect();
                delay(100);
            }
            if (!wifiScanEntered) {
                wifiScanEntered = true;
                startWiFiScan();
            }
            if (wifiScanState == 0 && !scanningPaused && now - lastScan > SCAN_INTERVAL_MS) {
                startWiFiScan();
                lastScan = now;
            }
            processWiFiScan();
            updateTargetTracking();
            if (now - targetPulseTimer > PULSE_INTERVAL_MS) {
                pulseSize = (pulseSize + 1) % 7;
                targetPulseTimer = now;
            }
            geigerSound();
            cleanupDevices();
            if (now - lastDrawTime > DRAW_INTERVAL_MS) {
                drawWiFiList();
                frameBuffer.pushSprite(0, 0);
                lastDrawTime = now;
            }
            break;

        // ------------------------------------------------
        // CONFIG AP MODE (60s timer, then back to menu)
        // ------------------------------------------------
        case APP_CONFIG:
            if (!webUIActive) {
                Serial.println("[BOOT] Starting WiFi AP for config...");
                startWebUI();
                webUIActive = true;
                apStartTime = now;
                apClientEverConnected = false;
                frameBuffer.fillScreen(TFT_BLACK);
            }
            if (WiFi.softAPgetStationNum() > 0) {
                apClientEverConnected = true;
            }
            if (!apClientEverConnected && now - apStartTime > 60000) {
                Serial.println("[BOOT] AP timeout — returning to menu");
                stopWebUI();
                webUIActive = false;
                appState = APP_MENU;
                break;
            }
            if (webUIActive) {
                handleWebUI();
                if (!configDrawn) {
                    configDrawn = true;
                    frameBuffer.fillScreen(TFT_BLACK);
                    frameBuffer.setTextColor(TFT_GREEN);
                    frameBuffer.setTextSize(2);
                    frameBuffer.setCursor(45, 40);
                    frameBuffer.print("CONFIG AP");
                    frameBuffer.setTextSize(1);
                    frameBuffer.setCursor(35, 80);
                    frameBuffer.print("SSID: Tripwire-xxxx");
                    frameBuffer.setCursor(35, 100);
                    frameBuffer.print("IP: 192.168.4.1");
                    frameBuffer.setCursor(35, 130);
                    frameBuffer.print("Connect to configure");
                    frameBuffer.setCursor(35, 160);
                    frameBuffer.print("or hold to return");
                    frameBuffer.setTextColor(TFT_DARKGREEN);
                    frameBuffer.setCursor(55, 218);
                    frameBuffer.print("HOLD TO RETURN");
                    frameBuffer.pushSprite(0, 0);
                }
            }
            break;

        // ------------------------------------------------
        // ABOUT SCREEN
        // ------------------------------------------------
        case APP_ABOUT:
            if (!aboutDrawn) {
                drawAbout();
                aboutDrawn = true;
            }
            break;

        // ------------------------------------------------
        // DEAUTH DETECTOR (menu item)
        // ------------------------------------------------
        case APP_DEAUTH:
            if (!deauthDrawn) {
                deauthDrawn = true;
                deauthCount = 0;
                deauthDetected = false;
                deauthChannel = 1;
                deauthChanTimer = millis();
                strcpy(deauthLastSrc, "none");
                drawDeauthScreen();
                if (!deauthActive) {
                    Serial.println("[DEAUTH] Starting sniffer...");
                    WiFi.disconnect(true);
                    delay(200);
                    esp_wifi_stop();
                    delay(100);
                    WiFi.mode(WIFI_STA);
                    delay(100);
                    esp_wifi_set_promiscuous_rx_cb(deauthSnifferCallback);
                    wifi_promiscuous_filter_t filt = {WIFI_PROMIS_FILTER_MASK_ALL};
                    esp_wifi_set_promiscuous_filter(&filt);
                    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
                    esp_wifi_set_promiscuous(true);
                    deauthActive = true;
                    Serial.println("[DEAUTH] Sniffer active");
                }
            }
            // Channel hop every 300ms
            if (millis() - deauthChanTimer > 300) {
                deauthChanTimer = millis();
                deauthChannel = (deauthChannel % 11) + 1;
                esp_wifi_set_channel(deauthChannel, WIFI_SECOND_CHAN_NONE);
            }
            if (deauthDetected) {
                deauthDetected = false;
                deauthFlashUntil = millis() + 100;
                tone(BUZZER_PIN, 4000, 10);
                // Update counter + last source
                frameBuffer.fillRect(100, 100, 60, 12, TFT_BLACK);
                frameBuffer.setTextColor(TFT_YELLOW);
                frameBuffer.setCursor(100, 100);
                frameBuffer.print(deauthCount);
                frameBuffer.fillRect(20, 145, 200, 12, TFT_BLACK);
                frameBuffer.setTextColor(TFT_ORANGE);
                frameBuffer.setCursor(20, 145);
                frameBuffer.print(deauthLastSrc);
            }
            if (millis() < deauthFlashUntil) {
                frameBuffer.fillRect(70, 60, 100, 6, TFT_RED);
            } else {
                frameBuffer.fillRect(70, 60, 100, 6, TFT_BLACK);
            }
            frameBuffer.pushSprite(0, 0);
            break;

        // ------------------------------------------------
        // DEVICE HUNTER (pick target → track live RSSI)
        // ------------------------------------------------
        case APP_HUNTER:
#ifndef DISABLE_BLE
            if (!hunterDrawn) {
                if (pBLEScan == NULL) {
                    delay(10);
                    NimBLEDevice::init("");
                    pBLEScan = NimBLEDevice::getScan();
                    pBLEScan->setScanCallbacks(new MyScanCallbacks());
                    pBLEScan->setActiveScan(true);
                }
                hunterPicking = true;
                hunterHunting = false;
                hunterPickIndex = 0;
                hunterTargetMac[0] = '\0';
                hunterTargetName[0] = '\0';
                hunterTargetRssi = -100;
                hunterPrevLevel = 0;
                drawHunterPickScreen();
                hunterDrawn = true;
            }

            if (hunterPicking) {
                // Touch is handled in handleTouch() — just wait for selection
            }

            if (hunterHunting) {
                if (!bleScanBusy && (millis() - tailsLastScan >= 500)) {
                    tailsLastScan = millis();
                    startBLEScan();
                }
                processBLEScan();

                if (!bleScanBusy) {
                    // Find target in current scan results
                    bool found = false;
                    for (int i = 0; i < deviceCount; i++) {
                        if (strcmp(devices[i].mac, hunterTargetMac) == 0) {
                            hunterTargetRssi = devices[i].rssi;
                            if (devices[i].name[0]) {
                                strncpy(hunterTargetName, devices[i].name, 23);
                                hunterTargetName[23] = '\0';
                            }
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        hunterTargetRssi = max(hunterTargetRssi - 1, -100);
                    }

                    // Signal-adaptive beep
                    int level = (hunterTargetRssi >= -35) ? 4 : (hunterTargetRssi >= -55) ? 3 :
                                (hunterTargetRssi >= -75) ? 2 : 1;
                    unsigned long beepInterval = 0;
                    switch (level) {
                        case 4: beepInterval = 200; break;
                        case 3: beepInterval = 400; break;
                        case 2: beepInterval = 800; break;
                        default: beepInterval = 1600; break;
                    }
                    if (level != hunterPrevLevel) {
                        hunterPrevLevel = level;
                        int freq = 1800 + level * 500;
                        int dur = 20 + level * 15;
                        tone(BUZZER_PIN, freq, dur);
                        hunterBeepTimer = millis();
                    } else if (millis() - hunterBeepTimer >= beepInterval) {
                        hunterBeepTimer = millis();
                        int freq = 1800 + level * 500;
                        int dur = 12 + level * 8;
                        tone(BUZZER_PIN, freq, dur);
                    }

                    // Update web globals for dashboard visibility
                    tripwireStrongestRssi = hunterTargetRssi;
                    if (hunterTargetName[0]) {
                        strncpy(tripwireStrongestName, hunterTargetName, 23);
                        tripwireStrongestName[23] = '\0';
                    }
                    strncpy(tripwireLastNewMac, hunterTargetMac, 17);
                    tripwireLastNewMac[17] = '\0';
                    tripwireBaselineCount = 1;

                    drawHuntScreen();
                }
            }
#else
            frameBuffer.fillScreen(TFT_BLACK);
            frameBuffer.setTextColor(TFT_RED);
            frameBuffer.setTextSize(2);
            frameBuffer.setCursor(20, 100);
            frameBuffer.print("HUNT NOT AVAILABLE");
            frameBuffer.setTextSize(1);
            frameBuffer.setTextColor(TFT_WHITE);
            frameBuffer.setCursor(15, 140);
            frameBuffer.print("Hunt requires BLE");
            frameBuffer.setTextColor(TFT_DARKGREEN);
            frameBuffer.setCursor(40, 218);
            frameBuffer.print("HOLD TO RETURN");
            frameBuffer.pushSprite(0, 0);
#endif
            break;

        // ------------------------------------------------
        // WIFI HUNT (pick AP → periodic scan for RSSI)
        // ------------------------------------------------
        case APP_WIFI_HUNT:
            if (!wifiHuntDrawn) {
                wifiHuntPicking = true;
                wifiHuntHunting = false;
                wifiHuntPickIndex = 0;
                wifiHuntTargetBssid[0] = '\0';
                wifiHuntTargetSsid[0] = '\0';
                wifiHuntTargetRssi = -100;
                wifiHuntPrevLevel = 0;
                wifiHuntSniffing = false;
                wifiHuntPacketTimer = millis();
                wifiHuntLastSignalMs = millis();
                drawWifiHuntPickScreen();
                wifiHuntDrawn = true;
            }

            if (wifiHuntPicking) {
                // Touch handled in handleTouch()
            }

            if (wifiHuntHunting) {
                // Set STA mode and lock to target channel on first entry
                if (!wifiHuntSniffing && wifiHuntTargetChannel > 0) {
                    WiFi.disconnect(true);
                    delay(100);
                    esp_wifi_stop();
                    delay(100);
                    WiFi.mode(WIFI_STA);
                    delay(100);
                    esp_wifi_set_channel(wifiHuntTargetChannel, WIFI_SECOND_CHAN_NONE);
                    wifiHuntSniffing = true;
                    wifiHuntPacketTimer = millis();
                    wifiHuntLastSignalMs = millis();
                }

                // Every 250ms, do a fast directed scan for accurate RSSI
                if (millis() - wifiHuntPacketTimer >= 250) {
                    wifiHuntPacketTimer = millis();
                    int rssi = wifiHuntFastScan();
                    if (rssi > -100) {
                        wifiHuntTargetRssi = rssi;
                        wifiHuntLastSignalMs = millis();
                        Serial.printf("[WIFI HUNT] RSSI: %d\n", rssi);
                    }
                }

                // Decay after 2s of no actual signal (AP disappeared)
                if (millis() - wifiHuntLastSignalMs > 2000) {
                    wifiHuntTargetRssi = max(-100, wifiHuntTargetRssi - 1);
                }

                // Signal-adaptive beep
                int level = (wifiHuntTargetRssi >= -35) ? 4 : (wifiHuntTargetRssi >= -55) ? 3 :
                            (wifiHuntTargetRssi >= -75) ? 2 : 1;
                unsigned long beepInterval = 0;
                switch (level) {
                    case 4: beepInterval = 200; break;
                    case 3: beepInterval = 400; break;
                    case 2: beepInterval = 800; break;
                    default: beepInterval = 1600; break;
                }
                if (level != wifiHuntPrevLevel) {
                    wifiHuntPrevLevel = level;
                    int freq = 1800 + level * 500;
                    int dur = 20 + level * 15;
                    tone(BUZZER_PIN, freq, dur);
                    wifiHuntBeepTimer = millis();
                } else if (millis() - wifiHuntBeepTimer >= beepInterval) {
                    wifiHuntBeepTimer = millis();
                    int freq = 1800 + level * 500;
                    int dur = 12 + level * 8;
                    tone(BUZZER_PIN, freq, dur);
                }

                // Update web globals
                tripwireStrongestRssi = wifiHuntTargetRssi;
                if (wifiHuntTargetSsid[0]) {
                    strncpy(tripwireStrongestName, wifiHuntTargetSsid, 23);
                    tripwireStrongestName[23] = '\0';
                }
                strncpy(tripwireLastNewMac, wifiHuntTargetBssid, 17);
                tripwireLastNewMac[17] = '\0';
                tripwireBaselineCount = 1;

                // Redraw at 100ms for responsive updates
                if (millis() - wifiHuntRedrawTimer >= 100) {
                    wifiHuntRedrawTimer = millis();
                    drawWifiHuntScreen();
                }
            }
            break;

        // ------------------------------------------------
        // TRIPWIRE MODE (baseline → monitor)
        // ------------------------------------------------
        case APP_TRIPWIRE:
#ifndef DISABLE_BLE
            if (!tailsDrawn) {
                if (pBLEScan == NULL) {
                    delay(10);
                    NimBLEDevice::init("");
                    pBLEScan = NimBLEDevice::getScan();
                    pBLEScan->setScanCallbacks(new MyScanCallbacks());
                    pBLEScan->setActiveScan(true);
                }
                tailsLastScan = 0;
                tailSlotCount = 0;
                memset(tailSlots, 0, sizeof(tailSlots));
                tripwireAlertCount = 0;
                tripwireStrongestRssi = -100;
                tripwireStrongestMac[0] = '\0';
                tripwireStrongestName[0] = '\0';
                tripwireLastNewMac[0] = '\0';
                deviceCount = 0;
                drawTailsScreen();
                tailsDrawn = true;
            }

            // Timer-gated scan cycle
            if (!bleScanBusy && (millis() - tailsLastScan >= TAILS_SCAN_INTERVAL_MS)) {
                tailsLastScan = millis();
                startBLEScan();
            }
            processBLEScan();

            // When scan completes, update tails
            if (!bleScanBusy) {
                updateTails();

                // Beep for high-confidence alerts (cooldown)
                if (millis() - tailsBeepTimer > TAILS_BEEP_COOLDOWN_MS) {
                    int bestSeen = 0, bestRssi = -100;
                    for (int i = 0; i < tailSlotCount; i++) {
                        int s = tailSlots[i].seenCount;
                        if (s == 0) continue;
                        int r = getTailRssi(tailSlots[i].mac);
                        if (s > bestSeen || (s == bestSeen && r > bestRssi)) {
                            bestSeen = s; bestRssi = r;
                        }
                    }
                    if (bestSeen >= TAILS_ALERT_MIN && bestRssi >= TAILS_STRONG_RSSI) {
                        int lvl = (bestRssi >= -35) ? 4 : (bestRssi >= -55) ? 3 : (bestRssi >= -65) ? 2 : 1;
                        tone(BUZZER_PIN, 2000 + lvl * 600, 40 + lvl * 20);
                        tailsBeepTimer = millis();
                    }
                }

                drawTailsScreen();
            }
#else
            frameBuffer.fillScreen(TFT_BLACK);
            frameBuffer.setTextColor(TFT_RED);
            frameBuffer.setTextSize(2);
            frameBuffer.setCursor(10, 100);
            frameBuffer.print("TRIPWIRE UNAVAILABLE");
            frameBuffer.setTextSize(1);
            frameBuffer.setTextColor(TFT_WHITE);
            frameBuffer.setCursor(15, 140);
            frameBuffer.print("Tripwire requires BLE");
            frameBuffer.setTextColor(TFT_DARKGREEN);
            frameBuffer.setCursor(40, 218);
            frameBuffer.print("HOLD TO RETURN");
            frameBuffer.pushSprite(0, 0);
#endif
            break;

        // ------------------------------------------------
        // PRESENCE RADAR (ESP-NOW mmWave node)
        // ------------------------------------------------
        case APP_PRESENCE_RADAR:
            if (firstMenuDraw) {
                frameBuffer.fillScreen(TFT_BLACK);
                presenceRadar.init();
                if (!presenceRadar.isActive()) {
                    frameBuffer.setTextColor(TFT_RED);
                    frameBuffer.setTextSize(1);
                    frameBuffer.setCursor(40, 100);
                    frameBuffer.print("RADAR INIT FAILED");
                    frameBuffer.setTextColor(TFT_DARKGREEN);
                    frameBuffer.setCursor(40, 218);
                    frameBuffer.print("HOLD TO RETURN");
                    frameBuffer.pushSprite(0, 0);
                }
                firstMenuDraw = false;
            }
            if (presenceRadar.isActive()) {
                presenceRadar.update();
            }
            break;
    }

    // ========================================================
    // PENTEST MODES (C5-safe: evil twin + MAC rand detection only)
    // ========================================================
    switch (appState) {
        case APP_EVIL_TWIN:
            if (!tailsDrawn) {
                tft.fillScreen(TFT_BLACK);
                evilTwinScan();
                tailsDrawn = true;
            }
            evilTwinDraw();
            delay(5000);
            appState = APP_MENU;
            break;

        case APP_MAC_RAND:
            if (!tailsDrawn) {
                tft.fillScreen(TFT_BLACK);
                macRandDetect();
                tailsDrawn = true;
            }
            macRandDraw();
            delay(5000);
            appState = APP_MENU;
            break;
    }

    yield();
}
