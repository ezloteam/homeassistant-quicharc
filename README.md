# QuicHarc for Home Assistant

Remote access to your Home Assistant through your Ezlo account. The QuicHarc app on your phone connects straight to Home Assistant over QUIC, and through a relay when a direct connection isn't possible. A browser can reach Home Assistant through Ezlo's servers, behind the Ezlo sign-in. Nothing needs to be opened on your router.

## Requirements

- Home Assistant 2026.4 or later (OS, Container or Core) on 64-bit Linux, x86_64 or ARM (aarch64).
- An Ezlo account with Home Assistant remote access. Without it, Home Assistant shows a repair saying the account needs a subscription, with a link to get one.
- The `my` integration, which `default_config:` includes. Sign in with Ezlo returns through my.home-assistant.io.

## Installation

With [HACS](https://hacs.xyz):
1. HACS → three-dot menu → **Custom repositories**: add `https://github.com/ezloteam/homeassistant-quicharc`, type **Integration**.
2. Search for **QuicHarc**, download it, and restart Home Assistant.

By hand: copy `custom_components/quicharc` into your Home Assistant `config/custom_components/` and restart.

## Setup

**Settings → Devices & services → Add integration → QuicHarc**:
1. **Sign in with Ezlo.** If my.home-assistant.io asks for your Home Assistant's address, enter the one you use to open Home Assistant.
2. **Home Assistant owner:** the Home Assistant user that your own devices and Ezlo's cloud services act as.
3. **HTTP settings:** so Home Assistant sees the real address of remote visitors (for IP bans, login notifications and logs), QuicHarc can trust its own connection to Home Assistant (`use_x_forwarded_for` with `trusted_proxies: [127.0.0.1, ::1]`). Home Assistant applies HTTP settings when it restarts, so you can restart right away (the default) or later. If Home Assistant can't use the change, it's undone.

QuicHarc then downloads its agent, checks its signature, registers this Home Assistant with your Ezlo account and connects.

## Using it

- **Your phone:** sign in to the QuicHarc app with the same Ezlo account. Your own devices are approved automatically (you can turn that off in the integration's options). A device signed in to another Ezlo account appears as a repair, **{device} wants remote access**, where you approve or deny it and choose the Home Assistant user it acts as. Deleting a device's token in your Home Assistant profile, or the **QuicHarc: Revoke device** action, removes its access.
- **Web access** (switch, off by default): lets a browser reach Home Assistant through Ezlo, after the Ezlo sign-in, at the address the **Web access URL** sensor shows (`https://<home id>.quicharc.ezlo.com`).
- **Ezlo device sync** (switch, off by default): lets Ezlo's cloud see and control your Home Assistant devices. Turning it off withdraws that access and deletes its token.
- **Notifications:** with Ezlo device sync on, `notify.quicharc` sends a notification to your phone through Ezlo.
- **Status:** the integration's device shows the agent, the connection to Ezlo, its round-trip time, the active path to your devices (local, direct or relay), the number of connected devices, whether Home Assistant sees real client addresses, and the **Web access URL** while web access is on and usable.

## Repairs

QuicHarc raises a repair, under **Settings → System → Repairs**, when it needs you:
- **Ezlo remote access needs a subscription**, or **subscription ended**, with a link to subscribe or renew. QuicHarc reconnects by itself a few minutes after the account has access.
- **Restart Home Assistant for QuicHarc**, when the HTTP settings changed. Submit to restart.
- **Set QuicHarc's proxy settings in Home Assistant**, when your configuration can't be changed automatically. It shows what to add.
- **This home's identity is in use on another installation**, when a restored backup or a cloned machine runs with the same remote access identity. Choose whether this installation or the other one keeps remote access.
- Also: the agent isn't running or failed verification, this machine isn't supported, or Home Assistant's clock is wrong.

## Network

QuicHarc's agent runs next to Home Assistant and only makes outgoing connections to Ezlo. All direct connections from your devices share one UDP port, chosen at random in 49152–65535 the first time and then kept. To make direct connections from outside your home possible, the agent asks your router to forward that port to it (PCP, then NAT-PMP, then UPnP-IGD), with a lease of a few minutes that it renews while it runs and removes when it stops. If your router doesn't answer, nothing changes and connections go through the relay.

## Privacy

QuicHarc always sends Ezlo's support team what it does, so problems can be diagnosed without asking you to read logs; there is no option to turn it off.
- **Where:** `https://ot.ezlo.com`, Ezlo's telemetry service.
- **What:** traces of sign-in, registration, the agent's download, start and restarts, device pairing, the switches, the HTTP settings change, notifications and repairs; QuicHarc's own log messages at INFO and above; counters of agent restarts, pairings and open repairs. The agent sends its own connection telemetry.
- **Identified by:** the QuicHarc and Home Assistant versions, this installation's Home Assistant instance id, and the Ezlo home, device and user ids.
- **Never:** tokens, keys, cookies, passwords, email addresses, device names, notification text, or any Home Assistant entity, state, dashboard or camera data. IP addresses in log messages are cut to their network (/24 or /48).

The integration's diagnostics download lists what this installation sends and how much was sent, queued or dropped.

## Removing

Delete the integration under **Settings → Devices & services**. QuicHarc removes the tokens it created for your devices and Ezlo's services, and unregisters this Home Assistant from your Ezlo account.

## Support

Report problems at [github.com/ezloteam/homeassistant-quicharc/issues](https://github.com/ezloteam/homeassistant-quicharc/issues). Attach the integration's diagnostics download; it holds no tokens or passwords.

## License

This software is subject to the terms of the "Ezlo Available Source License Agreement" (EASL); see [LICENSE](LICENSE).
