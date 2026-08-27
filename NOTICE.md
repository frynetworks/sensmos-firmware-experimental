# NOTICE

This repository was split out of [frynetworks/sensmos-firmware](https://github.com/frynetworks/sensmos-firmware)
to keep that fork's history clean for an eventual upstream pull request.

## Upstream credit

This firmware is a port of **[Galusz/sensmos-firmware](https://github.com/Galusz/sensmos-firmware)**
(ESP32, Arduino). All protocol design, module architecture, and node logic originate from that
upstream project. See [LICENSE](LICENSE) for full attribution and licensing terms.

## Why this is a separate repository

The ESP8266 port's realistic maximum free heap is **28-36 KB**, which is below the **60 KB**
minimum upstream states as the supported-board baseline. Keeping this port in its own repository,
rather than in the `frynetworks/sensmos-firmware` fork, keeps that fork's commit history free of
ESP8266-specific workarounds and constraints that don't apply to boards meeting the upstream
hardware baseline — so the fork can be offered upstream as a clean pull request.
