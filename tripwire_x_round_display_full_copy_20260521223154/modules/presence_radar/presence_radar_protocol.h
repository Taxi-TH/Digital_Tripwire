#pragma once
#include <Arduino.h>
#include <stdint.h>

#define NODE_ID "MMWAVE01"
#define NODE_MAC_ADDR {0xXX, 0xXX, 0xXX, 0xXX, 0xXX, 0xXX}

#define PRESENCE_RADAR_MAX_DATA_LEN 32

enum RadarCommand : uint8_t {
    CMD_PING        = 0x01,
    CMD_GET_STATUS  = 0x02,
    CMD_START_SCAN  = 0x03,
    CMD_STOP_SCAN   = 0x04,
};

enum RadarResponse : uint8_t {
    RSP_STATUS          = 0x81,
    RSP_HEARTBEAT       = 0x82,
    RSP_PRESENCE_UPDATE = 0x83,
    RSP_ERROR           = 0x84,
    RSP_PONG            = 0x85,
};

enum RadarError : uint8_t {
    ERR_NONE        = 0x00,
    ERR_UNKNOWN_CMD = 0x01,
    ERR_BUSY        = 0x02,
    ERR_SENSOR_FAIL = 0x03,
};

enum PresenceState : uint8_t {
    PRESENCE_CLEAR   = 0x00,
    PRESENCE_STATIC  = 0x01,
    PRESENCE_MOVING  = 0x02,
};

struct RadarCommandPacket {
    uint8_t command;
    uint8_t seq;
} __attribute__((packed));

struct RadarStatusPacket {
    uint8_t response;
    uint8_t seq;
    uint8_t firmwareMajor;
    uint8_t firmwareMinor;
    uint16_t uptimeSeconds;
    uint16_t batteryMv;
    int8_t signalQuality;
} __attribute__((packed));

struct RadarHeartbeatPacket {
    uint8_t response;
    uint8_t seq;
    uint16_t uptimeSeconds;
    uint16_t batteryMv;
} __attribute__((packed));

struct RadarPresencePacket {
    uint8_t response;
    uint8_t seq;
    uint8_t presenceState;
    uint8_t hasTarget;
    uint8_t movingTarget;
    uint16_t distanceCm;
    uint8_t confidence;
} __attribute__((packed));

struct RadarErrorPacket {
    uint8_t response;
    uint8_t seq;
    uint8_t errorCode;
} __attribute__((packed));

enum NodeConnectionState {
    NODE_DISCONNECTED,
    NODE_CONNECTING,
    NODE_CONNECTED,
    NODE_TIMEOUT,
};

struct EventLogEntry {
    unsigned long timestamp;
    char message[24];
};
