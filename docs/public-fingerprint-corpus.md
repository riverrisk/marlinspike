# Public Fingerprinting Corpus

This is the first high-value working set selected from the public ICS Defense
PCAP archive at <https://icsdefense.net/en/pcap>. The archive itself is backed
by the public GitHub repository
[`EmreEkin/ICS-Pcaps`](https://github.com/EmreEkin/ICS-Pcaps).

These captures were chosen because they improve MarlinSpike's passive device
typing and DPI in places where role inference was still weak: controller vs
workstation separation, BACnet/BMS enrichment, IEC 104 telemetry handling,
OPC UA server detection, and OT vendor/product-line extraction.

## Top 10 Picks

1. [`Ethernet_IP/ControlLogix_Logix5000_download_upload_run.pcap`](https://github.com/EmreEkin/ICS-Pcaps/raw/master/Ethernet_IP/ControlLogix_Logix5000_download_upload_run.pcap)
   - Rockwell ControlLogix identity object data, PLC vs Logix workstation traffic, engineering activity.
2. [`Ethernet_IP/ControlLogix_FactoryTalk_HMI.pcap`](https://github.com/EmreEkin/ICS-Pcaps/raw/master/Ethernet_IP/ControlLogix_FactoryTalk_HMI.pcap)
   - FactoryTalk-style supervisory behavior around a ControlLogix PLC.
3. [`Profinet/pro1.pcap`](https://github.com/EmreEkin/ICS-Pcaps/raw/master/Profinet/pro1.pcap)
   - PROFINET DCP station name, vendor ID, device ID, and role metadata.
4. [`Profinet/pro5.pcap`](https://github.com/EmreEkin/ICS-Pcaps/raw/master/Profinet/pro5.pcap)
   - Multiple Siemens station-name patterns (`switch*`, `pn-io`, `swln*`) that are useful for infrastructure typing.
5. [`S7COMM/1-S7comm-VarService-Read-DB1DBD0.pcap`](https://github.com/EmreEkin/ICS-Pcaps/raw/master/S7COMM/1-S7comm-VarService-Read-DB1DBD0.pcap)
   - Clean Siemens S7 request/response baseline for PLC and engineering traffic.
6. [`OPC-UA/opycua_share.pcap`](https://github.com/EmreEkin/ICS-Pcaps/raw/master/OPC-UA/opycua_share.pcap)
   - Minimal OPC UA server/client handshake with explicit `SecurityPolicy#None`.
7. [`BacNET/bacnet-ethernet-device.pcap`](https://github.com/EmreEkin/ICS-Pcaps/raw/master/BacNET/bacnet-ethernet-device.pcap)
   - BACnet vendor identifiers, device object metadata, and broadcast discovery.
8. [`IEC61850/Substation/ABB1.pcap`](https://github.com/EmreEkin/ICS-Pcaps/raw/master/IEC61850/Substation/ABB1.pcap)
   - MMS/IEC 61850 substation traffic for protective relay / IED handling.
9. [`IEC60870-104/iec104_baselines.pcap`](https://github.com/EmreEkin/ICS-Pcaps/raw/master/IEC60870-104/iec104_baselines.pcap)
   - Clear IEC 104 ASDU type/cause patterns for telemetry RTU inference.
10. [`OMRON/omrontest.pcap`](https://github.com/EmreEkin/ICS-Pcaps/raw/master/OMRON/omrontest.pcap)
    - Omron FINS controller model/version disclosure (`CP1L-EL20DR-D`) for direct PLC fingerprinting.

## Current Use In MarlinSpike

This corpus now directly informs:

- BACnet vendor ID enrichment and BMS device typing
- IEC 104 ASDU-aware telemetry / RTU classification
- Omron FINS controller model extraction
- stronger PLC preservation when CIP identity already identifies a PLC
- PROFINET station-name switch and IO-controller hints
- OPC UA server vs client distinction

## Next Additions

- Expand CIP vendor and device profile mappings from more public EtherNet/IP captures
- Add richer IEC 61850 MMS field extraction for relay and bay-controller signatures
- Add more BACnet vendor IDs and workstation/server product signatures
- Build tiny regression fixtures from these captures so role inference stays stable across releases
