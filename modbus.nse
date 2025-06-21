local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
This script queries devices on port 502 when the Modbus Application Protocol (MBAP) service is running. 
It attempts to communicate with all possible slave IDs (1–247) to identify responsive devices and retrieve basic information.

This script only targets Modbus TCP/IP services. It does not support or scan Modbus over serial (RTU/ASCII) connections.
]]

---
-- @usage
-- nmap -p 502 --script modbus.se --script-args modbus.discovery=true,modbus.aggressive=true <target>
--
-- @args discovery  - boolean value to send MEI Read Device Identificaiton request
-- @args aggressive - boolean value defines find all or just first sid
-- @args snapshot   - boolean value to query digital and analog 
-- @args type       - value deciding what register to query; either analog, digital or all 
--
-- @output
-- PORT    STATE SERVICE
-- 502/tcp open  mbap
-- | modbus_read_id:
-- |   Function Code: 0x2B
-- |   MEI Type: 0x0E
-- |   Device ID Code: 0x01
-- |   Conformity Level: 1
-- |   Number of ID Objects: 3
-- |   - Object 0: VendorName
-- |   - Object 1: ProductCode
-- |   - Object 2: Revision
-- |_  Script successfully ran.
--
-- PORT    STATE SERVICE REASON
-- 502/tcp open  mbap    syn-ack ttl 64
-- | modbus: 
-- |   Slave ID 1:
-- |   Register Value [1]: 10560
-- |   Register Value [2]: 0
-- |   Register Value [3]: 128
-- |   Register Value [4]: 192
-- |   Register Value [5]: 128
-- |   Register Value [6]: 0
-- |   Register Value [7]: 0
-- |_  Register Value [8]: 0

-- Version 0.1 - 2025-06-20 - Initial Release

author = "Martin Jakobsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "brute", "intrusive"}

-- Non-exhausted list: See -> for more https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf 
local modbus_functionCodes = {
  [0x01] = "Read Coils",
  [0x02] = "Read Discrete Inputs",
  [0x03] = "Read Holding Registers",
  [0x04] = "Read Input Registers",
  [0x2B] = "Encapsulated Interface",
  [0x81] = "Exception: Read Coils",
  [0x82] = "Exception: Read Discrete Inputs",
  [0x83] = "Exception: Read Holding Registers",
  [0x84] = "Exception: Read Input Registers",
  [0xAB] = "Modbus Encapsulated Interface (MEI)",
  [0x0E] = "Read Device Identification"
}

-- exception codes when shit goes sideways
local modbus_exceptionCodes = {
  [0x01] = "ILLEGAL FUNCTION",
  [0x02] = "ILLEGAL DATA ADDRESS",
  [0x03] = "ILLEGAL DATA VALUE",
  [0x04] = "SLAVE DEVICE FAILURE",
  [0x05] = "ACKNOWLEDGE",
  [0x06] = "SLAVE DEVICE BUSY",
  [0x08] = "MEMORY PARITY ERROR",
  [0x0A] = "GATEWAY PATH UNAVAILABLE",
  [0x0B] = "GATEWAY TARGET DEVICE FAILED TO RESPOND"
}

-- configuration class // DO YOUR CHANGES HERE !!!
local Config = {
    slaveID             = 1,        -- For specific querying.
    quantity            = 8,        -- How many coils to read.
    portNumber          = 502,      -- Default modbus/mbap port number.
    startAddressDigital = 800,      -- Default is based on a OpenPLC slave device.
    startAddressAnalog  = 100,      -- Default is based on a OpenPLC slave device.
    functionCode        = 0x04,     -- 
    timeout             = 1000,     -- When to give up.
    protocolID          = 0x0000,   --
}

-- configurations used to determine default values in calculations // DO YOUR CHANGES HERE !!!
local sensorConfig = {
    volts = 5.0
}

-- initial seed value
math.randomseed(os.time())

local MEI_TEST_DATA = "\0\0\0\0\0\x29\x64\x2B\x0E\x01\x01\xFF\x00\x03" ..
                         "\0\x12Schneider Electric" ..
                         "\1\x05PM710" ..
                         "\2\x07v03.110"


-- only run on ports running mbap and on configured port (default 502)
portrule = shortport.port_or_service(Config.portNumber, "mbap")


-- takes the jibberish bits and turn them into human readable language
local gobbledygookTranslator = function (response)
    if not response or #response < 9 then
        return "Invalid or incomplete MBAP response."
    end

    local rCode = response:byte(8)
    local rData = response:sub(9)

    -- transcript 
    local lines = {}

    -- Exception 
    if rCode >= 0x80  and rCode <= 0x85 then
        return string.format("Exception: 0x%02X -> %s", rCode, modbus_functionCodes[rCode])
    end

    if rCode == 0xAB then
        local excCode = rData:byte(1) or 0
        return string.format("Exception: 0x%02X -> %s", rCode, modbus_exceptionCodes[excCode] or ("Unknown exception code 0x" .. string.format("%02X", excCode)))
    end


    -- Heureka
    -- digital values 
    if rCode == 0x01 or rCode == 0x02 then
        local values = { rData:byte(2, 1 + rData:byte(1)) }
        local coil_number = 0

        -- checks for each coil number; defined in Config
        for _, byte_val in ipairs(values) do
            for bit = 0, 7 do
                coil_number = coil_number + 1
                if coil_number > Config.quantity then break end
                local bit_val = (byte_val >> bit) & 1
                table.insert(lines, string.format("Coil [%d] (Address %d): %s",
                    coil_number, Config.startAddressDigital + coil_number - 1,
                    bit_val == 1 and "ON" or "OFF"))
            end
            if coil_number >= Config.quantity then break end
        end

    -- analog values
    elseif rCode == 0x03 or rCode == 0x04 then
        local bCount = rData:byte(1)
        for i = 2, bCount, 2 do
            local chunk = rData:sub(i, i+1)
            if #chunk == 2 then
                local val = string.unpack(">I2", chunk)
                table.insert(lines, string.format("Register Value [%d]: %d", ((i - 1) // 2) + 1, val))
            end
        end

    else
        local name = modbus_functionCodes[rCode] or "Unknown"
        table.insert(lines, string.format("Unknown code 0x%02X (%s)", rCode, name))
    end

    return table.concat(lines, "\n")
end

-- psuedorandom value to filter out possbile false positives
local function getRandomTransactionID()
    return math.random(0, 0xFFFF)
end

-- takes a analog value (non-hex) and returns degrees in celsius
local tempSensorValue = function (sensorValue)
    local voltage = (sensorValue/1024.0) * sensorConfig.volts
    local temperature = (voltage - 0.5) * 100
    return temperature
end

-- builds the packet to send off to the PLCs
local packetAssemblyLine = function(slaveID, functionCode, data)
    local transactionID = getRandomTransactionID()
    -- checking uniqueness 
    stdnse.print_debug(1, "Transaction ID %d", transactionID)

    local mbap = string.pack(">I2I2I2B", transactionID, Config.protocolID, 1 + #data + 1, slaveID)
    local pdu = string.pack("B", functionCode) .. data
    return mbap .. pdu
end

-- opens up a connection to the host/port
-- !!! are not responsible for closing the connection !!!
-- "legacy" function, might use later; currently dead code since I opted to use comm.exchange
local function openSesame(host, port)
    local client = nmap.new_socket()
    local try = nmap.new_try(function() client:close() end)

    try(client:connect(host, port))
    client:set_timeout(3000)
    return client
end

-- sends our packets away and receives them
local callService = function(host, port, slaveID, functionCode, data)

    -- decide on address to query depending on analog / digital 
    if functionCode == 0x01 or functionCode == 0x02 then
        startAddress = Config.startAddressDigital
    elseif functionCode == 0x03 or functionCode == 0x04 then
        startAddress = Config.startAddressAnalog
    end

    if not data then
        data = string.pack(">I2I2", startAddress, Config.quantity)
    end

    local request = packetAssemblyLine(slaveID, functionCode, data)

    -- debug sending packet
    stdnse.print_debug(1, stdnse.tohex(request))

    local status, response = comm.exchange(host, port, request, { timeout = Config.timeout })
    if not status then return nil end

    return response
end

-- Nmap script entry point
action = function(host, port)

    -- get all args
    local discovery     = stdnse.get_script_args('modbus.discovery')
    local aggressive    = stdnse.get_script_args('modbus.aggressive')
    local snapshot      = stdnse.get_script_args('modbus.snapshot')
    local type          = stdnse.get_script_args('modbus.type')

    -- legacy open port
    local client        = openSesame(host, port)

    -- final printable table 
    local resultLines   = {}

    -- run Read Device Information on host
    -- !!! Not guaranteed to be implemented for all PLCs !!!
    if discovery then
        -- specifies that it's for MEI
        local data = string.pack("BBB", 0x0E, 0x01, 0x00)
        for sID = 1, 246 do
            stdnse.print_debug(1, "Currently querying slaveID : %s", sID)
            local discoveryResponse = callService(host, port, sID, 0x2B, data)
            if discoveryResponse then

                -- debug return packet
                stdnse.print_debug(1, stdnse.tohex(discoveryResponse))

                local r = gobbledygookTranslator(discoveryResponse)

                table.insert(resultLines, string.format("Slave ID %d:\n%s", sID, r))
            end
            -- If aggressive isn't turn on or if it's a illegal function (not implemented) then break.
            if (not aggressive) then
                stdnse.print_debug(1, "MEI might not be implamented")
                break end

        end
    end

    -- delivers a snaphot requested coils or registers
    -- !!! depending on the PLC this can be prone to duplicates even thought it responds with unique slaveID !!!
    if snapshot then
        -- queries all 246 if aggressive is set
        for sID = 1, 246 do
            stdnse.print_debug(1, "Currently querying slaveID : %s", sID)
            local snapshotResponse = callService(host, port, sID,Config.functionCode, nil)

            -- debug return packet
            --stdnse.print_debug(1, stdnse.tohex(snapshotResponse))
        
            local r = gobbledygookTranslator(snapshotResponse)
            table.insert(resultLines, string.format("Slave ID %d:\n%s", sID, r))

            if (not aggressive) then break end
        end
    end


    client:close()

    return stdnse.format_output(true, resultLines)
end




