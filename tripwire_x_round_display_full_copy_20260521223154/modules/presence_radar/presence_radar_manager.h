#pragma once
#include <Arduino.h>
#include <stdint.h>
#include "presence_radar_protocol.h"

#define RADAR_PEER_MAC {0x54, 0x32, 0x04, 0x12, 0x34, 0x56}

class PresenceRadarManager {
public:
    PresenceRadarManager();

    bool begin();
    void end();

    bool sendPing();
    bool sendGetStatus();
    bool sendStartScan();
    bool sendStopScan();

    NodeConnectionState connectionState() const;
    unsigned long lastResponseMs() const;
    int signalQuality() const;

    bool hasNewData() const;
    PresenceState currentPresence() const;
    bool hasTarget() const;
    bool targetMoving() const;
    uint16_t distanceCm() const;
    uint8_t confidence() const;

    uint8_t firmwareMajor() const;
    uint8_t firmwareMinor() const;
    uint16_t uptimeSeconds() const;
    uint16_t batteryMv() const;

    void update();
    void processRecv(const uint8_t* data, int len);

private:
    static const unsigned long CONNECTION_TIMEOUT_MS = 3000;
    static const unsigned long HEARTBEAT_TIMEOUT_MS = 10000;

    NodeConnectionState _connState;
    unsigned long _lastResponseMs;
    unsigned long _lastPingMs;
    unsigned long _lastHeartbeatMs;
    uint8_t _seq;
    int8_t _signalQuality;

    PresenceState _presence;
    bool _hasTarget;
    bool _targetMoving;
    uint16_t _distanceCm;
    uint8_t _confidence;

    uint8_t _fwMajor;
    uint8_t _fwMinor;
    uint16_t _uptime;
    uint16_t _batteryMv;

    bool _newData;
    bool _initialized;

    bool sendCommand(uint8_t cmd);
    void handlePong();
    void handleStatus(const uint8_t* data, int len);
    void handleHeartbeat(const uint8_t* data, int len);
    void handlePresenceUpdate(const uint8_t* data, int len);
    void handleError(const uint8_t* data, int len);
};
