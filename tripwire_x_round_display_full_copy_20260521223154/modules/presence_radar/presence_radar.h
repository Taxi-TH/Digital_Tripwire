#pragma once
#include <Arduino.h>
#include "presence_radar_protocol.h"

class PresenceRadarManager;
struct RadarDisplayData;

class PresenceRadar {
public:
    PresenceRadar();
    ~PresenceRadar();

    void init();
    void update();
    void cleanup();

    bool isActive() const;
    NodeConnectionState connectionState() const;

    void requestEventLog();
    void requestNodeHealth();

    bool eventLogVisible() const;
    bool nodeHealthVisible() const;
    int eventLogScroll() const;
    void scrollEventLog(int delta);

private:
    enum RadarScreen {
        SCREEN_CONNECTING,
        SCREEN_DASHBOARD,
        SCREEN_EVENT_LOG,
        SCREEN_NODE_HEALTH,
    };

    static const int MAX_EVENTS = 20;
    static const unsigned long PING_INTERVAL_MS = 5000;
    static const unsigned long STATUS_INTERVAL_MS = 10000;
    static const unsigned long RECONNECT_INTERVAL_MS = 3000;
    static const unsigned long REDRAW_INTERVAL_MS = 100;

    PresenceRadarManager* _manager;
    bool _active;
    RadarScreen _screen;
    unsigned long _lastPingMs;
    unsigned long _lastStatusMs;
    unsigned long _lastRedrawMs;
    unsigned long _lastReconnectMs;
    int _eventScroll;

    EventLogEntry _events[MAX_EVENTS];
    int _eventCount;

    RadarDisplayData _displayData;
    bool _showBattery;
    bool _initialized;

    void addEvent(const char* message);
    void updateDisplayData();
    void drawCurrentScreen();
    void handleConnectionTimeout();
    void handleReconnect();
};

extern PresenceRadar presenceRadar;
