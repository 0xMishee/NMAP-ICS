# ICS TCP/IP Discovery NSE Script

## Planned Feature  
This project is intended to grow beyond Modbus by adding support for querying other ICS/OT protocols (e.g., DNP3, S7, BACnet, etc.) to assist with broader industrial network reconnaissance and asset identification.

# S7Comm Discovery Script

## Description 

This script is primarily designed for scanning and querying devices that communicate using the S7Comm protocol. 
It builds upon the existing script bundled with Nmap, as well as the PLCScan tool by Positive Research (https://code.google.com/archive/p/plcscan/).
The secondary objective is to create an easy-to-modify script that can be adapted for various other purposes, 
with a clear and straightforward setup of the involved protocols for better readability and understanding.

## Usage

```bash
nmap -p 102 --script s7comm.nse <target/s>
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
# DNP3

## Description

This implementation uses OpenDNP3 and the DNP 3.0 Remote Communication Protocol for REC 523. It is primarily designed to identify active DNP3 source addresses by sending and analyzing data link layer packets. However, it can also be easily modified to send application layer packets.

The most notable difference between this script and others available online is that it does not send a predefined byte string. Instead, it dynamically generates the request string based on the user-selected address range, calculating the CRC-16 at runtime.
## Usage

```bash
nmap -p 20000 --script dnp3.nse <target/s>
```

```bash
PORT      STATE SERVICE REASON
20000/tcp open  dnp     syn-ack ttl 128
| dnp3: 
|   Control Code: LINK_STATUS
|   Source Address: 250
|_  Destination Address: 0
```

### Outstation Simulation 
```bash
	MASTER [31-Jul-2025 18:29:27.841] [TCP]: Request Link Status                                                                     
	DATA LINK Frame Octets (10)                                                                                                      
	05 64 05 C9 FA 00 00 00{12 DF}                                                                  
	Function                 Length  Control                       Source  Destination                                               
	Request Link Status      5       DIR:1 PRM:1 FCV:0             0       250                                                       

	OUTSTATION [31-Jul-2025 18:29:27.903] [TCP]: Link Status                                                                         
	DATA LINK Frame Octets (10)                                                                                                      
	05 64 05 0B 00 00 FA 00{80 B3}                                                                  
	Function                 Length  Control                       Source  Destination                                               
	Link Status              5       DIR:0 PRM:0 FCV:0             250     0                                                         
```

```bash
MASTER [31-Jul-2025 18:29:27.934] [TCP]: Unconfirmed User Data                                                                   
DATA LINK Frame Octets (10)                                                                                                      
05 64 05 C4 FA 00 00 00{45 25}                                                                  
Function                 Length  Control                       Source  Destination                                               
Unconfirmed User Data    5       DIR:1 PRM:1 FCV:0             0       250                                                       

OUTSTATION [31-Jul-2025 18:29:28.012] [TCP]: Response: Time_delay                                                                
DATA LINK Frame Octets (23)                                                                                                      
05 64 10 44 00 00 FA 00{29 BF}C0 00 81 90 00 34 01 07 01 88 13{C1 6A}                           
Function                 Length  Control                       Source  Destination                                               
Unconfirmed User Data    16      DIR:0 PRM:1 FCV:0             250     0                                                         
Transport: FIN:1 FIR:1 SEQ:0                                                                                                     
APPLICATION Layer                                                                                                                
Function           Control              Internal Indications                                                                     
Response           FIR:0 FIN:0 CON:0    Need_Time Restart                                                                        
									UNS:0 SEQ:0                                                                                                   
Object                       Variation                     Qualifier                                                             
52:Time Delay                1:Coarse                      0x07:Count 1                                                          
 Index Value          Flags                    Time                                                                             
 0                                             5000 milliseconds          
```

# Modbus TCP/IP Discovery NSE Script

This Nmap NSE (Nmap Scripting Engine) script is designed to discover and interact with devices using the Modbus TCP/IP protocol on port 502. It probes Modbus-compatible devices by querying slave IDs to identify active units, retrieve basic device information and register values. 

## Description

The script communicates with devices speaking the Modbus Application Protocol (MBAP) over TCP/IP. It iterates through Modbus slave IDs (1–247 by if aggressive mode is on) and sends requests to extract information such as vendor name, product code, and revision. It is particularly useful for mapping SCADA/ICS environments.

You can also choose to take snapshots of the register values and send the analog values to transformers to see if represents something tangible. 

**NOTE:** This script does not support Modbus over serial (RTU/ASCII) interfaces.

## Usage

```bash
nmap -p 502 --script modbus.nse --script-args modbus.discovery=true,modbus.aggressive=true <target/s>
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


# Reference Material 

## S7

- Configuration limits for products of 
the SIMATIC NET PC Software V13: https://cache.industry.siemens.com/dl/files/599/15227599/att_840968/v1/15227599_quantitystructure_and_performancedata_v13_e.pdf
- Error Codes: https://gmiru.com/resources/s7proto/constants.txt
- The Siemens S7 Communication - Part 1 General Structure: https://gmiru.com/article/s7comm/
- s7-info.nse: https://svn.nmap.org/nmap/scripts/s7-info.nse
- The Siemens S7 Communication - Part 2 Job Requests and Ack Data: https://gmiru.com/article/s7comm-part2/
- S7 PCAPs: https://github.com/gymgit/s7-pcaps
- S7 C implementation: https://github.com/0xMishee/S7COMMM-Plus

