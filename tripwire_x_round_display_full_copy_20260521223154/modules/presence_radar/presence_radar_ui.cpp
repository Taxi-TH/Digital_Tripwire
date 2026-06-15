#include "presence_radar_ui.h"
#include <TFT_eSPI.h>

extern TFT_eSprite frameBuffer;

uint16_t radarColorClear()   { return frameBuffer.color565(0, 255, 80); }
uint16_t radarColorStatic()  { return frameBuffer.color565(255, 180, 0); }
uint16_t radarColorMoving()  { return frameBuffer.color565(255, 40, 40); }
uint16_t radarColorAlert()   { return frameBuffer.color565(255, 0, 0); }
uint16_t radarColorText()    { return frameBuffer.color565(220, 220, 220); }
uint16_t radarColorGrid()    { return frameBuffer.color565(40, 40, 40); }

static uint16_t statusColor(const RadarDisplayData& data) {
    if (data.connState != NODE_CONNECTED) return radarColorGrid();
    if (data.distanceCm > 0 && data.distanceCm < 100) return radarColorAlert();
    if (data.presence == PRESENCE_MOVING) return radarColorMoving();
    if (data.presence == PRESENCE_STATIC) return radarColorStatic();
    return radarColorClear();
}

void radarUiInit() {
}

void radarUiDrawConnection() {
    frameBuffer.fillScreen(TFT_BLACK);
    frameBuffer.setTextSize(1);

    frameBuffer.setTextColor(radarColorClear());
    frameBuffer.setCursor(60, 40);
    frameBuffer.print("PRESENCE RADAR");

    frameBuffer.setTextColor(radarColorGrid());
    frameBuffer.setCursor(72, 70);
    frameBuffer.print("CONNECTING");

    frameBuffer.setTextColor(radarColorText());
    frameBuffer.setCursor(55, 95);
    frameBuffer.print("TO NODE");

    frameBuffer.setTextColor(radarColorMoving());
    frameBuffer.setCursor(72, 115);
    frameBuffer.print(NODE_ID);

    frameBuffer.setTextColor(radarColorGrid());
    frameBuffer.setCursor(85, 145);
    frameBuffer.print("WAITING...");

    static unsigned long dotTimer = 0;
    static int dotCount = 0;
    if (millis() - dotTimer > 500) {
        dotTimer = millis();
        dotCount = (dotCount + 1) % 4;
    }
    frameBuffer.setTextColor(radarColorClear());
    frameBuffer.setCursor(102, 145);
    for (int i = 0; i < dotCount; i++) frameBuffer.print(".");

    frameBuffer.pushSprite(0, 0);
}

void radarUiDrawDashboard(const RadarDisplayData& data) {
    frameBuffer.fillScreen(TFT_BLACK);

    uint16_t sColor = statusColor(data);

    frameBuffer.setTextSize(1);
    frameBuffer.setTextColor(radarColorClear());
    frameBuffer.setCursor(50, 4);
    frameBuffer.print("PRESENCE RADAR");

    frameBuffer.drawFastHLine(0, 16, 240, radarColorGrid());

    frameBuffer.setTextColor(sColor);
    frameBuffer.setCursor(8, 20);
    frameBuffer.print("STATUS");

    const char* statusText = "CLEAR";
    uint16_t stColor = radarColorClear();

    if (data.connState != NODE_CONNECTED) {
        statusText = "OFFLINE";
        stColor = radarColorGrid();
    } else if (data.distanceCm > 0 && data.distanceCm < 100) {
        statusText = "ALERT";
        stColor = radarColorAlert();
    } else if (data.presence == PRESENCE_MOVING) {
        statusText = "MOVEMENT";
        stColor = radarColorMoving();
    } else if (data.presence == PRESENCE_STATIC) {
        statusText = "DETECTED";
        stColor = radarColorStatic();
    }

    frameBuffer.setTextColor(stColor);
    frameBuffer.setCursor(60, 20);
    frameBuffer.print(statusText);

    frameBuffer.drawFastHLine(0, 32, 240, radarColorGrid());

    int dataY = 36;
    int lineH = 10;
    frameBuffer.setTextSize(1);

    frameBuffer.setTextColor(radarColorGrid());
    frameBuffer.setCursor(10, dataY);
    frameBuffer.print("PRESENCE");
    frameBuffer.setTextColor(sColor);
    frameBuffer.setCursor(90, dataY);
    frameBuffer.print(data.hasTarget ? "YES" : "NO");
    dataY += lineH;

    frameBuffer.setTextColor(radarColorGrid());
    frameBuffer.setCursor(10, dataY);
    frameBuffer.print("MOVEMENT");
    frameBuffer.setTextColor(sColor);
    frameBuffer.setCursor(90, dataY);
    if (!data.hasTarget) {
        frameBuffer.print("NONE");
    } else {
        frameBuffer.print(data.movingTarget ? "ACTIVE" : "STATIC");
    }
    dataY += lineH;

    frameBuffer.setTextColor(radarColorGrid());
    frameBuffer.setCursor(10, dataY);
    frameBuffer.print("DISTANCE");
    frameBuffer.setTextColor(sColor);
    frameBuffer.setCursor(90, dataY);
    if (data.hasTarget && data.distanceCm > 0) {
        char d[8];
        if (data.distanceCm >= 100) {
            snprintf(d, 8, "%u.%01uM", data.distanceCm / 100, (data.distanceCm % 100) / 10);
        } else {
            snprintf(d, 8, "%uCM", data.distanceCm);
        }
        frameBuffer.print(d);
    } else {
        frameBuffer.print("--");
    }
    dataY += lineH;

    frameBuffer.setTextColor(radarColorGrid());
    frameBuffer.setCursor(10, dataY);
    frameBuffer.print("CONFIDENCE");
    frameBuffer.setTextColor(sColor);
    frameBuffer.setCursor(90, dataY);
    if (data.hasTarget) {
        frameBuffer.printf("%u%%", data.confidence);
    } else {
        frameBuffer.print("--");
    }
    dataY += lineH + 2;

    frameBuffer.drawFastHLine(0, dataY, 240, radarColorGrid());
    dataY += 2;
}

void radarUiDrawRadarVisual(const RadarDisplayData& data) {
    const int cx = 120;
    const int cy = 200;
    const int maxRadius = 48;
    static unsigned long pulseTimer = 0;
    static int pulsePhase = 0;

    uint16_t sColor = statusColor(data);

    if (millis() - pulseTimer > 500) {
        pulseTimer = millis();
        pulsePhase = (pulsePhase + 1) % 4;
    }

    int radii[] = {10, 20, 30, 40, 48};
    for (int i = 0; i < 5; i++) {
        frameBuffer.drawCircle(cx, cy, radii[i], radarColorGrid());
    }

    frameBuffer.setTextSize(1);
    frameBuffer.setTextColor(radarColorGrid());
    frameBuffer.setCursor(cx - 19, cy - 52);
    frameBuffer.print("1M 2M 3M 4M 5M");

    frameBuffer.drawLine(cx, cy - maxRadius, cx, cy + maxRadius, radarColorGrid());
    frameBuffer.drawLine(cx - maxRadius, cy, cx + maxRadius, cy, radarColorGrid());

    if (data.hasTarget && data.connState == NODE_CONNECTED) {
        int targetRadius = map(data.confidence, 0, 100, 3, 14);
        targetRadius = constrain(targetRadius, 3, 14);

        if (data.distanceCm > 0 && data.distanceCm < 100) {
            targetRadius = 18;
            static unsigned long alertPulse = 0;
            if (millis() - alertPulse > 250) {
                alertPulse = millis();
            }
            int ap = (millis() % 500) < 250 ? 0 : 1;
            for (int r = targetRadius + 6; r <= targetRadius + 14; r += 4) {
                if ((ap + r) % 2 == 0) continue;
                frameBuffer.drawCircle(cx, cy, r, sColor);
            }
        } else if (data.presence == PRESENCE_MOVING) {
            static unsigned long movePulse = 0;
            if (millis() - movePulse > 350) {
                movePulse = millis();
            }
            for (int r = targetRadius + 4; r <= targetRadius + 10; r += 3) {
                if ((pulsePhase + r) % 2 == 0) continue;
                frameBuffer.drawCircle(cx, cy, r, sColor);
            }
        } else if (data.presence == PRESENCE_STATIC) {
            for (int r = targetRadius + 4; r <= targetRadius + 8; r += 3) {
                if ((pulsePhase + r) % 2 == 0) continue;
                frameBuffer.drawCircle(cx, cy, r, sColor);
            }
        } else {
            if (pulsePhase % 2 == 0) {
                frameBuffer.drawCircle(cx, cy, 6, sColor);
            }
        }

        uint16_t fillColor = sColor;
        frameBuffer.fillCircle(cx, cy, targetRadius, fillColor);
    } else {
        if (pulsePhase == 0 || pulsePhase == 2) {
            frameBuffer.drawCircle(cx, cy, 3, radarColorGrid());
        }
    }

    frameBuffer.pushSprite(0, 0);
}

void radarUiDrawEventLog(EventLogEntry* events, int count, int scrollOffset) {
    frameBuffer.fillScreen(TFT_BLACK);
    frameBuffer.setTextSize(1);

    frameBuffer.setTextColor(radarColorClear());
    frameBuffer.setCursor(60, 4);
    frameBuffer.print("EVENT LOG");

    frameBuffer.drawFastHLine(0, 16, 240, radarColorGrid());

    int y = 20;
    int visible = min(count - scrollOffset, 18);
    for (int i = scrollOffset; i < scrollOffset + visible && i < count; i++) {
        if (y > 230) break;

        unsigned long t = events[i].timestamp;
        int sec = (t / 1000) % 60;
        int min = (t / 60000) % 60;

        frameBuffer.setTextColor(radarColorGrid());
        frameBuffer.setCursor(5, y);
        frameBuffer.printf("%02d:%02d", min, sec);
        frameBuffer.setCursor(40, y);
        frameBuffer.setTextColor(radarColorText());
        frameBuffer.print(events[i].message);
        y += 10;
    }

    frameBuffer.pushSprite(0, 0);
}

void radarUiDrawStatusBar(const RadarDisplayData& data, bool showBattery) {
    frameBuffer.drawFastHLine(0, 0, 240, radarColorGrid());

    frameBuffer.setTextSize(1);
    const char* statusIcon = "OFF";
    uint16_t statusCol = radarColorGrid();

    if (data.connState == NODE_CONNECTING) {
        statusIcon = "---";
        statusCol = radarColorStatic();
    } else if (data.connState == NODE_CONNECTED) {
        statusIcon = "ON";
        statusCol = radarColorClear();
    }

    frameBuffer.setTextColor(statusCol);
    frameBuffer.setCursor(2, 2);
    frameBuffer.print("NODE:");
    frameBuffer.print(statusIcon);

    if (showBattery && data.batteryMv > 0) {
        frameBuffer.setTextColor(radarColorText());
        frameBuffer.setCursor(100, 2);
        frameBuffer.printf("%u.%01uV", data.batteryMv / 1000, (data.batteryMv % 1000) / 100);
    }

    unsigned long now = millis();
    int sec = (now / 1000) % 60;
    int min = (now / 60000) % 60;
    frameBuffer.setTextColor(radarColorGrid());
    frameBuffer.setCursor(180, 2);
    frameBuffer.printf("%02d:%02d", min, sec);

    frameBuffer.drawFastHLine(0, 12, 240, radarColorGrid());
}

void radarUiDrawNodeHealth(const RadarDisplayData& data) {
    frameBuffer.fillScreen(TFT_BLACK);
    frameBuffer.setTextSize(1);

    frameBuffer.setTextColor(radarColorClear());
    frameBuffer.setCursor(60, 4);
    frameBuffer.print("NODE HEALTH");

    frameBuffer.drawFastHLine(0, 16, 240, radarColorGrid());

    int y = 22;
    int lh = 10;

    frameBuffer.setTextColor(radarColorGrid());
    frameBuffer.setCursor(10, y);    frameBuffer.print("FIRMWARE");
    frameBuffer.setTextColor(radarColorText());
    frameBuffer.setCursor(110, y);
    frameBuffer.printf("v%u.%u", data.fwMajor, data.fwMinor);
    y += lh;

    frameBuffer.setTextColor(radarColorGrid());
    frameBuffer.setCursor(10, y);    frameBuffer.print("BATTERY");
    frameBuffer.setTextColor(radarColorText());
    frameBuffer.setCursor(110, y);
    if (data.batteryMv > 0) {
        frameBuffer.printf("%u.%01uV", data.batteryMv / 1000, (data.batteryMv % 1000) / 100);
    } else {
        frameBuffer.print("N/A");
    }
    y += lh;

    frameBuffer.setTextColor(radarColorGrid());
    frameBuffer.setCursor(10, y);    frameBuffer.print("UPTIME");
    frameBuffer.setTextColor(radarColorText());
    frameBuffer.setCursor(110, y);
    {
        int up = data.uptime;
        int h = up / 3600;
        int m = (up % 3600) / 60;
        int s = up % 60;
        frameBuffer.printf("%02d:%02d:%02d", h, m, s);
    }
    y += lh;

    frameBuffer.setTextColor(radarColorGrid());
    frameBuffer.setCursor(10, y);    frameBuffer.print("SIGNAL");
    frameBuffer.setTextColor(radarColorText());
    frameBuffer.setCursor(110, y);
    if (data.signalQuality >= 0) {
        frameBuffer.printf("%d dBm", data.signalQuality);
    } else {
        frameBuffer.print("--");
    }
    y += lh;

    frameBuffer.setTextColor(radarColorGrid());
    frameBuffer.setCursor(10, y);    frameBuffer.print("NODE ID");
    frameBuffer.setTextColor(radarColorText());
    frameBuffer.setCursor(110, y);
    frameBuffer.print(NODE_ID);

    frameBuffer.pushSprite(0, 0);
}
