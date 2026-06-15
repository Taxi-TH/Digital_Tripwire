#include "presence_radar_manager.h"
#include <esp_now.h>
#include <WiFi.h>

static PresenceRadarManager* g_managerInstance = NULL;

static const uint8_t peerMac[] = RADAR_PEER_MAC;

static void onDataRecv(const esp_now_recv_info_t* info, const uint8_t* data, int len) {
    if (g_managerInstance) {
        g_managerInstance->processRecv(data, len);
    }
}

static void onDataSent(const esp_now_send_info_t* info, esp_now_send_status_t status) {
    (void)info;
    (void)status;
}

PresenceRadarManager::PresenceRadarManager()
    : _connState(NODE_DISCONNECTED)
    , _lastResponseMs(0)
    , _lastPingMs(0)
    , _lastHeartbeatMs(0)
    , _seq(0)
    , _signalQuality(-1)
    , _presence(PRESENCE_CLEAR)
    , _hasTarget(false)
    , _targetMoving(false)
    , _distanceCm(0)
    , _confidence(0)
    , _fwMajor(0)
    , _fwMinor(0)
    , _uptime(0)
    , _batteryMv(0)
    , _newData(false)
    , _initialized(false)
{
}

bool PresenceRadarManager::begin() {
    if (_initialized) return true;

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();

    if (esp_now_init() != ESP_OK) {
        return false;
    }

    esp_now_register_recv_cb(onDataRecv);
    esp_now_register_send_cb(onDataSent);

    esp_now_peer_info_t peer = {};
    memcpy(peer.peer_addr, peerMac, 6);
    peer.channel = 0;
    peer.ifidx = WIFI_IF_STA;
    peer.encrypt = false;

    if (esp_now_add_peer(&peer) != ESP_OK) {
        esp_now_deinit();
        return false;
    }

    g_managerInstance = this;
    _initialized = true;
    _connState = NODE_CONNECTING;
    _lastPingMs = millis();

    return true;
}

void PresenceRadarManager::end() {
    if (!_initialized) return;

    sendStopScan();
    delay(50);

    esp_now_unregister_recv_cb();
    esp_now_unregister_send_cb();

    const uint8_t* mac = peerMac;
    esp_now_del_peer(mac);
    esp_now_deinit();

    _initialized = false;
    _connState = NODE_DISCONNECTED;
    _newData = false;

    if (g_managerInstance == this) {
        g_managerInstance = NULL;
    }
}

bool PresenceRadarManager::sendCommand(uint8_t cmd) {
    if (!_initialized) return false;

    RadarCommandPacket pkt;
    pkt.command = cmd;
    pkt.seq = _seq++;

    esp_err_t err = esp_now_send(peerMac, (uint8_t*)&pkt, sizeof(pkt));
    return (err == ESP_OK);
}

bool PresenceRadarManager::sendPing() {
    return sendCommand(CMD_PING);
}

bool PresenceRadarManager::sendGetStatus() {
    return sendCommand(CMD_GET_STATUS);
}

bool PresenceRadarManager::sendStartScan() {
    return sendCommand(CMD_START_SCAN);
}

bool PresenceRadarManager::sendStopScan() {
    return sendCommand(CMD_STOP_SCAN);
}

void PresenceRadarManager::update() {
    if (!_initialized) return;

    unsigned long now = millis();

    switch (_connState) {
        case NODE_DISCONNECTED:
            break;

        case NODE_CONNECTING:
            if (now - _lastPingMs > 1000) {
                if (_lastPingMs == 0) {
                    _lastPingMs = now;
                }
                if (now - _lastPingMs > CONNECTION_TIMEOUT_MS) {
                    _connState = NODE_TIMEOUT;
                }
            }
            break;

        case NODE_CONNECTED:
            if (now - _lastResponseMs > HEARTBEAT_TIMEOUT_MS) {
                _connState = NODE_TIMEOUT;
            }
            break;

        case NODE_TIMEOUT:
            break;
    }
}

NodeConnectionState PresenceRadarManager::connectionState() const {
    return _connState;
}

unsigned long PresenceRadarManager::lastResponseMs() const {
    return _lastResponseMs;
}

int PresenceRadarManager::signalQuality() const {
    return _signalQuality;
}

bool PresenceRadarManager::hasNewData() const {
    return _newData;
}

PresenceState PresenceRadarManager::currentPresence() const {
    return _presence;
}

bool PresenceRadarManager::hasTarget() const {
    return _hasTarget;
}

bool PresenceRadarManager::targetMoving() const {
    return _targetMoving;
}

uint16_t PresenceRadarManager::distanceCm() const {
    return _distanceCm;
}

uint8_t PresenceRadarManager::confidence() const {
    return _confidence;
}

uint8_t PresenceRadarManager::firmwareMajor() const {
    return _fwMajor;
}

uint8_t PresenceRadarManager::firmwareMinor() const {
    return _fwMinor;
}

uint16_t PresenceRadarManager::uptimeSeconds() const {
    return _uptime;
}

uint16_t PresenceRadarManager::batteryMv() const {
    return _batteryMv;
}

void PresenceRadarManager::processRecv(const uint8_t* data, int len) {
    if (!data || len < 1) return;

    uint8_t responseType = data[0];
    _lastResponseMs = millis();

    switch (responseType) {
        case RSP_PONG:
            handlePong();
            break;
        case RSP_STATUS:
            handleStatus(data, len);
            break;
        case RSP_HEARTBEAT:
            handleHeartbeat(data, len);
            break;
        case RSP_PRESENCE_UPDATE:
            handlePresenceUpdate(data, len);
            break;
        case RSP_ERROR:
            handleError(data, len);
            break;
    }
}

void PresenceRadarManager::handlePong() {
    if (_connState == NODE_CONNECTING) {
        _connState = NODE_CONNECTED;
    }
    _lastHeartbeatMs = millis();
}

void PresenceRadarManager::handleStatus(const uint8_t* data, int len) {
    if (len < (int)sizeof(RadarStatusPacket)) return;
    RadarStatusPacket* pkt = (RadarStatusPacket*)data;
    _fwMajor = pkt->firmwareMajor;
    _fwMinor = pkt->firmwareMinor;
    _uptime = pkt->uptimeSeconds;
    _batteryMv = pkt->batteryMv;
    _signalQuality = pkt->signalQuality;
}

void PresenceRadarManager::handleHeartbeat(const uint8_t* data, int len) {
    if (len < (int)sizeof(RadarHeartbeatPacket)) return;
    RadarHeartbeatPacket* pkt = (RadarHeartbeatPacket*)data;
    _uptime = pkt->uptimeSeconds;
    _batteryMv = pkt->batteryMv;
    _lastHeartbeatMs = millis();
}

void PresenceRadarManager::handlePresenceUpdate(const uint8_t* data, int len) {
    if (len < (int)sizeof(RadarPresencePacket)) return;
    RadarPresencePacket* pkt = (RadarPresencePacket*)data;
    _presence = (PresenceState)pkt->presenceState;
    _hasTarget = pkt->hasTarget;
    _targetMoving = pkt->movingTarget;
    _distanceCm = pkt->distanceCm;
    _confidence = pkt->confidence;
    _newData = true;
}

void PresenceRadarManager::handleError(const uint8_t* data, int len) {
    (void)data;
    (void)len;
}
