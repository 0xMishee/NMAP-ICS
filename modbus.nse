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
-- @args discovery          - boolean value to send MEI Read Device Identificaiton request
-- @args aggressive         - boolean value defines find all or just first sid
-- @args snapshot           - boolean value to query digital and analog 
-- @args functioncode       - value deciding what register to query; 0x01 -> 0x04
-- @args slaveid            - For targeting specific slave device
--
--  @output
--  PORT    STATE SERVICE
--  502/tcp open  mbap
-- | modbus: 
-- |   Slave ID 1:
-- |     Conformity Level: Basic Identificaiton
-- |     Number of Objects: 4
-- |     Object 0x00: Witte Software
-- |     Object 0x01: Modbus Slave
-- |     Object 0x02: V9.5.0, Build 2346
-- |     Object 0x03: https://www.modbustools.com/
-- |   Slave ID 1:
-- |   Register Value [1]: 10432
-- |   Celsius: 29.59
-- |   Coil [1] (Address 800): OFF
-- |   Coil [2] (Address 801): ON


-- Version 0.1 - 2025-06-22 - Initial Release

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

-- informs on how complete the identification is
local modbus_ConformityLevels = {
    [0x01] = "Basic Identificaiton",
    [0x02] = "Regular Identification",
    [0x03] = "Extended Identificaiton"
}

-- configuration class // DO YOUR CHANGES HERE !!!
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

-- get all arguments
local Arguments = {
    slaveID                 = stdnse.get_script_args('modbus.slaveid'),                   -- For specific querying a slaveID
    snapshot                = stdnse.get_script_args('modbus.snapshot'),                  -- To query all or some registers
    functionCode            = tonumber(stdnse.get_script_args('modbus.functioncode')),    -- What register for snapshot
    discovery               = stdnse.get_script_args('modbus.discovery'),                 -- Boolean in you want to qer
    aggressive              = stdnse.get_script_args('modbus.aggressive'),                -- If you want to go through all 246 possible slaves

}

-- configurations used to determine default values in calculations // DO YOUR CHANGES HERE !!!
local sensorConfig = {
    volts = 5.0
}

-- initial seed value
math.randomseed(os.time())

-- only run on ports running mbap and on configured port (default 502)
portrule = shortport.port_or_service(Config.portNumber, "mbap")

-- pseudorandom value to filter out possible false positives
local function getRandomTransactionID()
    return math.random(0, 0xFFFF)
end

-- takes a analog value (non-hex) and returns degrees in celsius
local firelord = function (sensorValue)
    local voltage = (sensorValue/Config.ADC) * sensorConfig.volts
    local temperature = (voltage - .5) * 100
    return temperature
end

-- takes the jibberish bits and turn them into human readable language
local gobbledygookTranslator = function (response)
    if not response or #response < 9 then
        return "Invalid or incomplete MBAP response."
    end

    -- output table
    local results = stdnse.output_table()

    local rCode = response:byte(8)
    local rData = response:sub(9)
    local mType = response:byte(9)

    -- Exception 
    -- standard 
    if rCode >= 0x80  and rCode <= 0x85 then
        return string.format("Exception: 0x%02X -> %s", rCode, modbus_functionCodes[rCode])
    end

    -- MEI exception codes
    if rCode == 0xAB then
        local excCode = rData:byte(1) or 0
        return string.format("Exception: 0x%02X -> %s", rCode, modbus_exceptionCodes[excCode] or ("Unknown exception code 0x" .. string.format("%02X", excCode)))
    end

    -- digital values 
    if rCode == 0x01 or rCode == 0x02 then
        local values = { rData:byte(2, 1 + rData:byte(1)) }
        local coil_number = 0

        for _, byte_val in ipairs(values) do
            for bit = 0, 7 do
                coil_number = coil_number + 1
                if coil_number > Config.quantity then break end
                local bit_val = (byte_val >> bit) & 1
                results[string.format("Coil [%d] (Address %d)", coil_number, Config.startAddressDigital + coil_number - 1)] = bit_val == 1 and "ON" or "OFF"
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
                local key = string.format("Register Value [%d]", ((i - 1) // 2) + 1)
                results[key] = val

                if Config.transformer then
                    results["Celsius"] = string.format("%.2f", firelord(val))
                end
            end
        end

    -- MEI Type 0x0E (Read Device Identification)
    elseif rCode == 0x2B and mType == 0x0E then

        local meiOffset = 15
        local conformityLevel = modbus_ConformityLevels[response:byte(11)]
        local numberOfObjects = response:byte(14)

        stdnse.print_debug(1, "Number of Objects: %s", numberOfObjects)

        results["Conformity Level"] = conformityLevel
        results["Number of Objects"] = numberOfObjects

        for r = 1, numberOfObjects do
            local objectID = response:byte(meiOffset)
            local objectLen = response:byte(meiOffset + 1)
            local objectValue = response:sub(meiOffset + 2, meiOffset + 1 + objectLen)
            
            -- Insanity Check
            stdnse.print_debug(1, "\n objectID: %s\n Object Lenght: %s\n Object Value: %s", objectID, objectLen, objectValue)

            results[string.format("Object 0x%02X", objectID)] = objectValue

            meiOffset = meiOffset + 2 + objectLen
        end

    else
        local name = modbus_functionCodes[rCode] or "Unknown"
        results[string.format("Unknown code 0x%02X", rCode)] = name
    end

    return results
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

-- wish I stuck with one way of representing responses...
local function seniorFormattingExecutive(sID, r)
  if type(r) == "string" then
    -- Just return the string with the slave ID header
    return string.format("Slave ID %d:\n%s", sID, r)
  end

  local lines = { string.format("Slave ID %d:", sID) }
  for k, v in pairs(r) do
    table.insert(lines, string.format("  %s: %s", k, v))
  end
  return table.concat(lines, "\n")
end



-- main
action = function(host, port)

    -- final printable table 
    local resultLines = {}

    -- run Read Device Information on host
    -- !!! Not guaranteed to be implemented for all PLCs !!!
    if Arguments.discovery then
        -- specifies that it's for MEI
        local data = string.pack("BBB", 0x0E, 0x01, 0x00)
        for sID = 1, 246 do
            stdnse.print_debug(1, "Currently querying slaveID : %s", sID)
            local discoveryResponse = callService(host, port, sID, 0x2B, data)
            if discoveryResponse then

                -- return packet
                stdnse.print_debug(1, stdnse.tohex(discoveryResponse))

                local r = gobbledygookTranslator(discoveryResponse)

                table.insert(resultLines, seniorFormattingExecutive(sID, r))
            end
            -- If aggressive isn't turn on or if it's a illegal function (not implemented) then break.
            if (not Arguments.aggressive) then
                stdnse.print_debug(1, "MEI might not be implamented")
                break end
        end
    end

    -- delivers a snaphot requested coils or registers
    -- !!! depending on the PLC this can be prone to duplicates even thought it responds with unique slaveID !!!
    if Arguments.snapshot then

        -- default to reading coils if not defined
        if Arguments.functionCode == nil then Arguments.functionCode = 0x01 end

        -- queries all 246 if aggressive is set
        for sID = 1, 246 do
            stdnse.print_debug(1, "Currently querying slaveID : %s", sID)
            local snapshotResponse = callService(host, port, sID, Arguments.functionCode, nil)
            local r = gobbledygookTranslator(snapshotResponse)
            table.insert(resultLines, seniorFormattingExecutive(sID, r))
            if (not Arguments.aggressive) then break end
        end
    end

    -- for querying a specific slaveID and register
    if Arguments.slaveID then

        -- default to reading coils if not defined
        if Arguments.functionCode == nil then Arguments.functionCode = 0x01 end

        for i = 1, Config.pulse do
            stdnse.print_debug(1, "Currently querying slaveID : %s", Arguments.slaveID)
            local snapshotResponse = callService(host, port, Arguments.slaveID, Arguments.functionCode, nil)
            local r = gobbledygookTranslator(snapshotResponse)
            table.insert(resultLines, seniorFormattingExecutive(Arguments.slaveID, r))
        end
    end


    return stdnse.format_output(true, resultLines)
end
