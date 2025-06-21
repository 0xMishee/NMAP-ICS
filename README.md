# Modbus TCP/IP Discovery NSE Script

## Planned Feature  
This project is intended to grow beyond Modbus by adding support for querying other ICS/OT protocols (e.g., DNP3, S7, BACnet, etc.) to assist with broader industrial network reconnaissance and asset identification.

# Modbus TCP/IP Discovery NSE Script

This Nmap NSE (Nmap Scripting Engine) script is designed to discover and interact with devices using the Modbus TCP/IP protocol on port 502. It probes Modbus-compatible devices by querying slave IDs to identify active units and retrieve basic device information.

## Description

The script communicates with devices speaking the Modbus Application Protocol (MBAP) over TCP/IP. It iterates through Modbus slave IDs (1–247 by default) and sends diagnostic requests to extract information such as vendor name, product code, and revision. It is particularly useful for mapping SCADA/ICS environments.

**NOTE:** This script does not support Modbus over serial (RTU/ASCII) interfaces.

## Usage

```bash
nmap -p 502 --script modbus.se --script-args modbus.discovery=true,modbus.aggressive=true <target>
```

PORT    STATE SERVICE
502/tcp open  mbap
| modbus_read_id:
|   Function Code: 0x2B
|   MEI Type: 0x0E
|   Device ID Code: 0x01
|   Conformity Level: 1
|   Number of ID Objects: 3
|   - Object 0: VendorName
|   - Object 1: ProductCode
|   - Object 2: Revision
|_  Script successfully ran.

PORT    STATE SERVICE REASON
502/tcp open  mbap    syn-ack ttl 64
| modbus: 
|   Slave ID 1:
|   Exception: 0xAB -> ILLEGAL FUNCTION
|   Slave ID 2:
|   Exception: 0xAB -> ILLEGAL FUNCTION

### Configure

You can tweak the behavior of the script by modifying the following internal parameters:

```lua
local Config = {
    slaveID        = 1,
    quantity       = 8,
    portNumber     = 502,
    startAddress   = 800,
    functionCode   = 0x01,
    timeout        = 1000,
    transactionID  = 0x0001,
    protocolID     = 0x0000,
}

local sensorConfig = {
    volts = 5.0
}
```