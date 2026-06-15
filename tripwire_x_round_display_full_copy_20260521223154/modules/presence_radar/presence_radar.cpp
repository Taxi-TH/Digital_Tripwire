#include "presence_radar.h"
#include "presence_radar_manager.h"
#include "presence_radar_ui.h"

PresenceRadar presenceRadar;

PresenceRadar::PresenceRadar()
    : _manager(NULL)
    , _active(false)
    , _screen(SCREEN_CONNECTING)
    , _lastPingMs(0)
    , _lastStatusMs(0)
    , _lastRedrawMs(0)
    , _lastReconnectMs(0)
    , _eventScroll(0)
    , _eventCount(0)
    , _showBattery(true)
    , _initialized(false)
{
    for (int i = 0; i < MAX_EVENTS; i++) {
        _events[i].timestamp = 0;
        _events[i].message[0] = '\0';
    }
}

PresenceRadar::~PresenceRadar() {
    cleanup();
}

void PresenceRadar::init() {
    if (_initialized) return;

    _manager = new PresenceRadarManager();
    if (!_manager->begin()) {
        delete _manager;
        _manager = NULL;
        _active = false;
        return;
    }

    _active = true;
    _screen = SCREEN_CONNECTING;
    _lastPingMs = millis();
    _lastReconnectMs = 0;
    _eventScroll = 0;
    _eventCount = 0;
    _initialized = true;

    addEvent("NODE CONNECTING");

    radarUiInit();
    radarUiDrawConnection();
}

void PresenceRadar::update() {
    if (!_active || !_manager) return;

    unsigned long now = millis();
    _manager->update();

    NodeConnectionState state = _manager->connectionState();

    switch (state) {
        case NODE_DISCONNECTED:
            if (now - _lastReconnectMs > RECONNECT_INTERVAL_MS) {
                _lastReconnectMs = now;
                _manager->begin();
                _screen = SCREEN_CONNECTING;
                radarUiDrawConnection();
            }
            break;

        case NODE_CONNECTING:
            if (now - _lastPingMs > PING_INTERVAL_MS) {
                _lastPingMs = now;
                _manager->sendPing();
            }
            if (now - _lastPingMs > 3000 && _lastPingMs > 0) {
                handleConnectionTimeout();
            }
            _screen = SCREEN_CONNECTING;
            if (now - _lastRedrawMs > REDRAW_INTERVAL_MS) {
                _lastRedrawMs = now;
                radarUiDrawConnection();
            }
            break;

        case NODE_CONNECTED:
            if (_screen == SCREEN_CONNECTING) {
                addEvent("NODE CONNECTED");
                _screen = SCREEN_DASHBOARD;
                _manager->sendStartScan();
                addEvent("SCAN STARTED");
            }

            if (now - _lastPingMs > PING_INTERVAL_MS) {
                _lastPingMs = now;
                _manager->sendPing();
            }
            if (now - _lastStatusMs > STATUS_INTERVAL_MS) {
                _lastStatusMs = now;
                _manager->sendGetStatus();
            }

            if (_manager->hasNewData()) {
                updateDisplayData();
            }

            if (now - _lastRedrawMs > REDRAW_INTERVAL_MS) {
                _lastRedrawMs = now;
                drawCurrentScreen();
            }
            break;

        case NODE_TIMEOUT:
            if (_screen == SCREEN_DASHBOARD) {
                addEvent("NODE LOST");
            }
            _screen = SCREEN_CONNECTING;
            _manager->end();
            handleReconnect();
            break;
    }
}

void PresenceRadar::cleanup() {
    if (!_initialized) return;

    if (_manager) {
        if (_manager->connectionState() == NODE_CONNECTED) {
            _manager->sendStopScan();
            delay(30);
        }
        _manager->end();
        delete _manager;
        _manager = NULL;
    }

    for (int i = 0; i < MAX_EVENTS; i++) {
        _events[i].timestamp = 0;
        _events[i].message[0] = '\0';
    }
    _eventCount = 0;

    _active = false;
    _initialized = false;
}

bool PresenceRadar::isActive() const {
    return _active;
}

NodeConnectionState PresenceRadar::connectionState() const {
    if (!_manager) return NODE_DISCONNECTED;
    return _manager->connectionState();
}

void PresenceRadar::requestEventLog() {
    _screen = SCREEN_EVENT_LOG;
    _eventScroll = 0;
    drawCurrentScreen();
}

void PresenceRadar::requestNodeHealth() {
    _screen = SCREEN_NODE_HEALTH;
    if (_manager) _manager->sendGetStatus();
    drawCurrentScreen();
}

bool PresenceRadar::eventLogVisible() const {
    return _screen == SCREEN_EVENT_LOG;
}

bool PresenceRadar::nodeHealthVisible() const {
    return _screen == SCREEN_NODE_HEALTH;
}

int PresenceRadar::eventLogScroll() const {
    return _eventScroll;
}

void PresenceRadar::scrollEventLog(int delta) {
    _eventScroll += delta;
    if (_eventScroll < 0) _eventScroll = 0;
    if (_eventScroll >= _eventCount) _eventScroll = _eventCount - 1;
    drawCurrentScreen();
}

void PresenceRadar::addEvent(const char* message) {
    if (_eventCount < MAX_EVENTS) {
        _events[_eventCount].timestamp = millis();
        strncpy(_events[_eventCount].message, message, 23);
        _events[_eventCount].message[23] = '\0';
        _eventCount++;
    } else {
        for (int i = 0; i < MAX_EVENTS - 1; i++) {
            _events[i] = _events[i + 1];
        }
        _events[MAX_EVENTS - 1].timestamp = millis();
        strncpy(_events[MAX_EVENTS - 1].message, message, 23);
        _events[MAX_EVENTS - 1].message[23] = '\0';
    }
}

void PresenceRadar::updateDisplayData() {
    if (!_manager) return;

    _displayData.connState = _manager->connectionState();
    _displayData.presence = _manager->currentPresence();
    _displayData.hasTarget = _manager->hasTarget();
    _displayData.movingTarget = _manager->targetMoving();
    _displayData.distanceCm = _manager->distanceCm();
    _displayData.confidence = _manager->confidence();
    _displayData.fwMajor = _manager->firmwareMajor();
    _displayData.fwMinor = _manager->firmwareMinor();
    _displayData.uptime = _manager->uptimeSeconds();
    _displayData.batteryMv = _manager->batteryMv();
    _displayData.signalQuality = _manager->signalQuality();
    _displayData.lastUpdate = millis();
    _displayData.events = _events;
    _displayData.eventCount = _eventCount;

    static PresenceState lastPresence = PRESENCE_CLEAR;
    static bool lastHasTarget = false;

    if (_manager->hasTarget() != lastHasTarget) {
        lastHasTarget = _manager->hasTarget();
        if (lastHasTarget) {
            addEvent("PRESENCE DETECTED");
        } else {
            addEvent("AREA CLEAR");
        }
    }

    if (_manager->hasTarget() && _manager->currentPresence() != lastPresence) {
        lastPresence = _manager->currentPresence();
        if (lastPresence == PRESENCE_MOVING) {
            addEvent("MOVEMENT DETECTED");
        } else if (lastPresence == PRESENCE_STATIC) {
            addEvent("STATIC TARGET");
        }
    }

    if (_manager->hasTarget() && _manager->distanceCm() > 0 && _manager->distanceCm() < 100) {
        static unsigned long lastAlert = 0;
        if (millis() - lastAlert > 5000) {
            lastAlert = millis();
            addEvent("ALERT CLOSE RANGE");
        }
    }
}

void PresenceRadar::drawCurrentScreen() {
    switch (_screen) {
        case SCREEN_CONNECTING:
            radarUiDrawConnection();
            break;
        case SCREEN_DASHBOARD:
            radarUiDrawDashboard(_displayData);
            radarUiDrawRadarVisual(_displayData);
            break;
        case SCREEN_EVENT_LOG:
            radarUiDrawEventLog(_events, _eventCount, _eventScroll);
            break;
        case SCREEN_NODE_HEALTH:
            radarUiDrawNodeHealth(_displayData);
            break;
    }
}

void PresenceRadar::handleConnectionTimeout() {
    if (!_manager) return;
    if (_manager->connectionState() == NODE_CONNECTING) {
        addEvent("CONNECTION TIMEOUT");
    }
}

void PresenceRadar::handleReconnect() {
    _lastReconnectMs = millis();
    _manager->begin();
    _screen = SCREEN_CONNECTING;
    addEvent("RECONNECTING...");
    radarUiDrawConnection();
}
