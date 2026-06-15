#pragma once
#include <Arduino.h>
#include "presence_radar_protocol.h"

struct RadarDisplayData {
    NodeConnectionState connState;
    PresenceState presence;
    bool hasTarget;
    bool movingTarget;
    uint16_t distanceCm;
    uint8_t confidence;
    uint8_t fwMajor;
    uint8_t fwMinor;
    uint16_t uptime;
    uint16_t batteryMv;
    int8_t signalQuality;
    unsigned long lastUpdate;
    EventLogEntry* events;
    int eventCount;
};

void radarUiInit();
void radarUiDrawConnection();
void radarUiDrawDashboard(const RadarDisplayData& data);
void radarUiDrawRadarVisual(const RadarDisplayData& data);
void radarUiDrawEventLog(EventLogEntry* events, int count, int scrollOffset);
void radarUiDrawStatusBar(const RadarDisplayData& data, bool showBattery);
void radarUiDrawNodeHealth(const RadarDisplayData& data);

uint16_t radarColorClear();
uint16_t radarColorStatic();
uint16_t radarColorMoving();
uint16_t radarColorAlert();
uint16_t radarColorText();
uint16_t radarColorGrid();
