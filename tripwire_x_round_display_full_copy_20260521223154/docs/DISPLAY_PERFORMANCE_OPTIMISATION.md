# TRIPWIRE — Display Performance Optimisation Task

> Reference spec for the Seeed Studio Round Display (240x240 GC9A01) on the XIAO ESP32-C5.
> Goal: eliminate flicker and tearing during Wi-Fi / BLE scans by introducing sprite-based double buffering.

## Objective

Eliminate screen flicker and tearing on the Seeed Studio Round Display (240x240 GC9A01) by implementing proper double-buffered rendering using `TFT_eSprite`. The current firmware redraws directly to the TFT during Wi-Fi and BLE scans, causing visible flickering, partial redraws and poor UI smoothness.

### Target Platform

- Seeed Studio XIAO ESP32-C5
- Seeed Studio Round Display
- Seeed_GFX / TFT_eSPI
- Tripwire firmware

---

## Required Changes

### 1. Implement Full-Screen Sprite Buffer

Create a global framebuffer sprite:

```cpp
TFT_eSPI tft = TFT_eSPI();
TFT_eSprite frameBuffer = TFT_eSprite(&tft);
```

In `setup()`:

```cpp
frameBuffer.setColorDepth(16);
frameBuffer.createSprite(240, 240);
```

All rendering must occur on the sprite, **not** directly on the TFT.

Replace all occurrences of:

- `tft.draw*`
- `tft.fill*`
- `tft.print*`
- `tft.pushImage*`

with:

- `frameBuffer.draw*`
- `frameBuffer.fill*`
- `frameBuffer.print*`
- `frameBuffer.pushImage*`

**except for the final frame transfer.**

At the end of every render cycle:

```cpp
frameBuffer.pushSprite(0, 0);
```

The TFT should only receive complete rendered frames.

### 2. Remove Full Screen Clearing

Locate all occurrences of `tft.fillScreen(...)` — especially inside:

- `loop()`
- radar rendering
- Wi-Fi rendering
- BLE rendering
- screen refresh functions

Replace with:

```cpp
frameBuffer.fillSprite(TFT_BLACK);
```

Only clear the sprite, never the physical display.

### 3. Create Static Background Layer

Build a persistent radar background sprite.

```cpp
TFT_eSprite bgSprite = TFT_eSprite(&tft);
```

In `setup()`:

```cpp
bgSprite.setColorDepth(16);
bgSprite.createSprite(240, 240);
bgSprite.fillSprite(TFT_BLACK);
```

Draw **ONLY ONCE**:

- radar rings
- crosshair
- static labels
- fixed UI decorations
- mode headers
- logo graphics

Do not redraw these every frame.

During refresh:

```cpp
frameBuffer.pushImage(
  0, 0, 240, 240,
  (uint16_t*)bgSprite.getPointer()
);
```

Then draw dynamic content on top.

### 4. Separate Static and Dynamic Content

**STATIC:**

- radar circles
- crosshair
- mode title
- frame borders
- logo

**DYNAMIC:**

- Wi-Fi targets
- BLE targets
- RSSI labels
- device counters
- sweep line
- target lock indicator

Only dynamic content should be redrawn.

### 5. Implement Asynchronous Wi-Fi Scanning

Replace blocking scans:

```cpp
WiFi.scanNetworks();
```

with:

```cpp
WiFi.scanNetworks(true);
```

Process results only when available:

```cpp
int count = WiFi.scanComplete();

if (count >= 0) {
  processResults();
  WiFi.scanDelete();
  WiFi.scanNetworks(true);
}
```

Display rendering must never wait for a Wi-Fi scan to finish.

### 6. Limit Display Refresh Rate

Add a dedicated frame timer. Target: **30 FPS maximum**.

```cpp
const uint32_t FRAME_TIME = 33;

if (millis() - lastFrame >= FRAME_TIME) {
  renderDisplay();
  lastFrame = millis();
}
```

Avoid rendering every `loop()` iteration.

### 7. Reduce Label Redraws

Only redraw SSID labels when:

- device appears
- device disappears
- RSSI changes significantly

Do not redraw all labels every frame.

### 8. Sweep Line Optimisation

The radar sweep line should be rendered independently.

Only erase the previous sweep line and draw the new sweep line.

Do not redraw the entire radar background.

### 9. Profile Render Performance

Add timing diagnostics:

```cpp
uint32_t start = millis();
renderDisplay();
Serial.printf("Frame Time: %lu ms\n", millis() - start);
```

**Targets:**

- <20 ms render time
- stable 30 FPS
- no visible flicker

---

## Expected Result

After optimisation:

- No visible screen flicker
- No tearing during Wi-Fi scans
- Smooth radar animation
- Stable touch responsiveness
- Lower SPI bandwidth usage
- Lower CPU load
- More professional UI appearance

Preserve all existing Tripwire functionality and visual appearance while restructuring rendering for sprite-based double buffering and asynchronous updates.
