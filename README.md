# ICS TCP/IP Discovery NSE Script

## Planned Feature  
This project is intended to grow beyond Modbus by adding support for querying other ICS/OT protocols (e.g., DNP3, S7, BACnet, etc.) to assist with broader industrial network reconnaissance and asset identification.

# S7Comm Discovery Script

## Description 

This script is primarily designed for scanning and querying devices that communicate using the S7Comm protocol. 
It builds upon the existing script bundled with Nmap, as well as the PLCScan tool by Positive Research.
The secondary objective is to create an easy-to-modify script that can be adapted for various other purposes, 
with a clear and straightforward setup of the involved protocols for better readability and understanding.

## Usage

```bash
nmap -p 102 --script s7comm.nse <target>
```

```bash
PORT    STATE SERVICE  REASON
102/tcp open  iso-tsap syn-ack ttl 64
| s7comm: 
|   Module: 6ES7 315-2EH14-0AB0 
|   Basic Hardware: 6ES7 315-2EH14-0AB0 
|   Version: 3.2.6
|   Automation System Name: SNAP7-SERVER
|   Module Type: CPU 315-2 PN/DP
|   Plant Identification: 
|   Copyright: Original Siemens Equipment
|_  Serial Number: S C-C2UR28922012
```

# Modbus TCP/IP Discovery NSE Script

This Nmap NSE (Nmap Scripting Engine) script is designed to discover and interact with devices using the Modbus TCP/IP protocol on port 502. It probes Modbus-compatible devices by querying slave IDs to identify active units, retrieve basic device information and register values. 

## Description

The script communicates with devices speaking the Modbus Application Protocol (MBAP) over TCP/IP. It iterates through Modbus slave IDs (1–247 by if aggressive mode is on) and sends requests to extract information such as vendor name, product code, and revision. It is particularly useful for mapping SCADA/ICS environments.

You can also choose to take snapshots of the register values and send the analog values to transformers to see if represents something tangible. 

**NOTE:** This script does not support Modbus over serial (RTU/ASCII) interfaces.

## Usage

```bash
nmap -p 502 --script modbus.nse --script-args modbus.discovery=true,modbus.aggressive=true <target>
```

```bash
 PORT    STATE SERVICE
 502/tcp open  mbap
| modbus: 
|   Slave ID 1:
|     Conformity Level: Basic Identificaiton
|     Number of Objects: 4
|     Object 0x00: Witte Software
|     Object 0x01: Modbus Slave
|     Object 0x02: V9.5.0, Build 2346
|     Object 0x03: https://www.modbustools.com/

PORT    STATE SERVICE REASON
502/tcp open  mbap    syn-ack ttl 64
| modbus: 
|   Slave ID 1:
|   Exception: 0xAB -> ILLEGAL FUNCTION
|   Slave ID 2:
|   Exception: 0xAB -> ILLEGAL FUNCTION

PORT    STATE SERVICE REASON
502/tcp open  mbap    syn-ack ttl 64
| modbus: 
|   Slave ID 1:
|   Coil [1] (Address 800): OFF
|   Coil [2] (Address 801): OFF
|   Coil [3] (Address 802): OFF
|   Coil [4] (Address 803): OFF
|   Coil [5] (Address 804): OFF
|   Coil [6] (Address 805): OFF
|   Coil [7] (Address 806): OFF
|_  Coil [8] (Address 807): OFF

PORT    STATE SERVICE REASON
502/tcp open  mbap    syn-ack ttl 64
| modbus: 
|   Slave ID 1:
|   Register Value [1]: 10560
|   Register Value [2]: 0
|   Register Value [3]: 128
|   Register Value [4]: 192
|   Register Value [5]: 128
|   Register Value [6]: 0
|   Register Value [7]: 0
|_  Register Value [8]: 0
```

### Configure

You can tweak the behavior of the script by modifying the following internal parameters:

```lua
local Config = {
    quantity            = 8,        -- How many coils to read.
    portNumber          = 502,      -- Default modbus/mbap port number.
    startAddressAnalog  = 100,      -- Default is based on a OpenPLC slave device.
    startAddressDigital = 800,      -- Default is based on a OpenPLC slave device.
    timeout             = 1000,     -- When to give up.
    protocolID          = 0x0000,   -- Always 0x0000 (reserved for future use...lol!)
    pulse               = 1,        -- How many times it will query the specific register
    transformer         = true,     -- Boolean, true if you want to send analog data to transform the data for suggestions.
    ADC                 = 65535.0   -- 5V modbus value range
}


local sensorConfig = {
    volts = 5.0
}
```
