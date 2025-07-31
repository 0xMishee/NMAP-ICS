local stdnse    = require "stdnse"
local shortport = require "shortport"
local table     = require "table"
local string    = require "string"
local comm      = require "comm"

description = [[
It sends link status queries to the specified address range to check which address are active.
]]


author = "Martin Jakobsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

---
-- @usage
-- nmap --script dnp3.nse --script-args=<arguments> -p 20000 <target/s>
--
-- @args portnumber     - Incase portnumber isn't standard 20000.
-- @args timeout        - Change timeout, otherwise it defaults to 1000.
-- @args address_size   - The x first addresses to run the script on, defaults to 100 first.
-- @args bomb           - Will run cold restart function on target/s. 
-- @args slow 					- Slowly send link status packages through the address range.

---
-- Arguments that can be modified.
local config = {

  portnumber    = stdnse.get_script_args('dnp3.port') or '20000',
  timeout       = stdnse.get_script_args('dnp3.timeout') or '4000',
  address_size  = stdnse.get_script_args('dnp3.address_size') or '0-100',
  bomb          = stdnse.get_script_args('dnp3.bomb') or "false",
  slow			= stdnse.get_script_args('dnp3.slow') or "false"

}

---
-- From Outstation to Master, don't care about our response codes. 
local control_codes = {
  [0x00] = 'ACK',
  [0x01] = 'NACK',            -- Link reset required
  [0x0B] = 'LINK_STATUS',
  [0x0F] = 'NOT_SUPPORTED',
  [0x10] = 'ACK',             -- Recieve Buffers full
  [0x11] = 'NACK',            -- Recieve Buffers full
  [0x1B] = 'LINK_STATUS',     -- Recieve Buffers full
  [0x1F] = 'NOT_SUPPORTED',   -- Recieve Buffers full
  [0x40] = 'RESET_LINK_STATES',   -- FCB = 0  
  [0x44] = 'UNFORMED_USER_DATA',  -- FCB = 0  
  [0x49] = 'REQUEST_LINK_STATES', -- FCB = 0  
  [0x52] = 'TEST_LINK_STATES',    -- FCB = 0  
  [0x53] = 'CONFIRMED_USER_DATA', -- FCB = 0  
  [0x60] = 'RESET_LINK_STATES',   -- FCB = 1
  [0x64] = 'UNFORMED_USER_DATA',  -- FCB = 1  
  [0x69] = 'REQUEST_LINK_STATES', -- FCB = 1  
  [0x72] = 'TEST_LINK_STATES',    -- FCB = 1  
  [0x73] = 'CONFIRMED_USER_DATA', -- FCB = 1  
}

---
-- Application layer function codes 
local function_codes = {
  confirm             = 0x00,
  read                = 0x01,
  write               = 0x02,
  select              = 0x03,
  operate             = 0x04,
  dir_operate         = 0x05,
  dir_operate_no_resp = 0x06,
  freeze              = 0x07,
  freeze_no_resp      = 0x08,
  freeze_clear        = 0x09,
  freeze_clear_no_resp = 0x0a,
  freeze_at_time      = 0x0b,
  cold_restart        = 0x0d,
  warm_restart        = 0x0e,
  initialize_data     = 0x0f,
  initialize_app      = 0x10,
  start_app           = 0x11,
  stop_app            = 0x12,
  save_configuration  = 0x13,
  enable_unsolicited  = 0x14,
  disabled_unsolicited = 0x15, 
  assign_class        = 0x16, 
  delay_measrement    = 0x17,
  record_current_time = 0x18,
  open_file           = 0x19,
  close_file          = 0x1a,
  delete_file         = 0x1b,
  get_file_information = 0x1c,
  authenticate_file   = 0x1d, 
}

---
-- 
local data_link_header = {
  start  = 0x0564,
  length = 0x05, 
  control = {
    direction         = 1, -- From Master to outstation. 
    primary           = 1, -- Request type packet.
    frame_count_bit   = 0, -- Checking or retransmissions: off (We're sending one big packet). 
    frame_count_valid = 0, -- Since FCB is off so should this, since it's just says to care about FCB. 
    reserved          = 0, 
    data_flow_control = 0, -- Since we're the master sending requests we turn this off, would tell the other end to stop sending. 
  },

-- All function codes that we can send to the outstation.
  function_codes = {
    RESET_LINK_STATES     = 0x00,	-- Reset Data Link Layer
    TEST_LINK_STATES      = 0x02, -- Verifies communication path.
    CONFIRMED_USER_DATA   = 0x03, -- Sends data with ack expected.
    UNCONFIRMED_USER_DATA = 0x04, -- Sends data without ack expected.
    REQUEST_LINK_STATUS   = 0x09, -- Check link status. 
  },
  
  source = 0x0000,
}

---
-- Dictates how application layer messager are handled.
local application_control = {

	FIR = 1, -- First Fragment
	FIN = 1, -- Last Fragment 
	CON = 0, -- Req confirmation
	UNS = 0, -- Unsolicitated response
	SEQ = 0  -- SEQ number

}

---
-- Handles fragmentation and reassembly.  We're only sending one package so nothing that needs to change.
local transport_header = {

	FIR = 1, 
	FIN = 1, 
	SEQ = 0,

}

-- Used to speed up polynomial calculations. 
local dnp3_crc_table = {
	   0x0000, 0x365E, 0x6CBC, 0x5AE2, 0xD978, 0xEF26, 0xB5C4, 0x839A, 0xFF89, 0xC9D7, 0x9335, 0xA56B, 0x26F1, 0x10AF,
       0x4A4D, 0x7C13, 0xB26B, 0x8435, 0xDED7, 0xE889, 0x6B13, 0x5D4D, 0x07AF, 0x31F1, 0x4DE2, 0x7BBC, 0x215E, 0x1700,
       0x949A, 0xA2C4, 0xF826, 0xCE78, 0x29AF, 0x1FF1, 0x4513, 0x734D, 0xF0D7, 0xC689, 0x9C6B, 0xAA35, 0xD626, 0xE078,
       0xBA9A, 0x8CC4, 0x0F5E, 0x3900, 0x63E2, 0x55BC, 0x9BC4, 0xAD9A, 0xF778, 0xC126, 0x42BC, 0x74E2, 0x2E00, 0x185E,
       0x644D, 0x5213, 0x08F1, 0x3EAF, 0xBD35, 0x8B6B, 0xD189, 0xE7D7, 0x535E, 0x6500, 0x3FE2, 0x09BC, 0x8A26, 0xBC78,
       0xE69A, 0xD0C4, 0xACD7, 0x9A89, 0xC06B, 0xF635, 0x75AF, 0x43F1, 0x1913, 0x2F4D, 0xE135, 0xD76B, 0x8D89, 0xBBD7,
       0x384D, 0x0E13, 0x54F1, 0x62AF, 0x1EBC, 0x28E2, 0x7200, 0x445E, 0xC7C4, 0xF19A, 0xAB78, 0x9D26, 0x7AF1, 0x4CAF,
       0x164D, 0x2013, 0xA389, 0x95D7, 0xCF35, 0xF96B, 0x8578, 0xB326, 0xE9C4, 0xDF9A, 0x5C00, 0x6A5E, 0x30BC, 0x06E2,
       0xC89A, 0xFEC4, 0xA426, 0x9278, 0x11E2, 0x27BC, 0x7D5E, 0x4B00, 0x3713, 0x014D, 0x5BAF, 0x6DF1, 0xEE6B, 0xD835,
       0x82D7, 0xB489, 0xA6BC, 0x90E2, 0xCA00, 0xFC5E, 0x7FC4, 0x499A, 0x1378, 0x2526, 0x5935, 0x6F6B, 0x3589, 0x03D7,
       0x804D, 0xB613, 0xECF1, 0xDAAF, 0x14D7, 0x2289, 0x786B, 0x4E35, 0xCDAF, 0xFBF1, 0xA113, 0x974D, 0xEB5E, 0xDD00,
       0x87E2, 0xB1BC, 0x3226, 0x0478, 0x5E9A, 0x68C4, 0x8F13, 0xB94D, 0xE3AF, 0xD5F1, 0x566B, 0x6035, 0x3AD7, 0x0C89,
       0x709A, 0x46C4, 0x1C26, 0x2A78, 0xA9E2, 0x9FBC, 0xC55E, 0xF300, 0x3D78, 0x0B26, 0x51C4, 0x679A, 0xE400, 0xD25E,
       0x88BC, 0xBEE2, 0xC2F1, 0xF4AF, 0xAE4D, 0x9813, 0x1B89, 0x2DD7, 0x7735, 0x416B, 0xF5E2, 0xC3BC, 0x995E, 0xAF00,
       0x2C9A, 0x1AC4, 0x4026, 0x7678, 0x0A6B, 0x3C35, 0x66D7, 0x5089, 0xD313, 0xE54D, 0xBFAF, 0x89F1, 0x4789, 0x71D7,
       0x2B35, 0x1D6B, 0x9EF1, 0xA8AF, 0xF24D, 0xC413, 0xB800, 0x8E5E, 0xD4BC, 0xE2E2, 0x6178, 0x5726, 0x0DC4, 0x3B9A,
       0xDC4D, 0xEA13, 0xB0F1, 0x86AF, 0x0535, 0x336B, 0x6989, 0x5FD7, 0x23C4, 0x159A, 0x4F78, 0x7926, 0xFABC, 0xCCE2,
       0x9600, 0xA05E, 0x6E26, 0x5878, 0x029A, 0x34C4, 0xB75E, 0x8100, 0xDBE2, 0xEDBC, 0x91AF, 0xA7F1, 0xFD13, 0xCB4D,
       0x48D7, 0x7E89, 0x246B, 0x1235}

-- Run only if these three are valid.
portrule = shortport.port_or_service(config.portnumber, "dnp3","tcp")

--- 
-- Calculates the hex value for the control field. Defaults to REQUEST_LINK_STATUS.
-- @param none
-- @returns control_value, hex value for the control field in data link layer.
local data_link_control_calc = function(function_code)
  return 
  (data_link_header.control.direction << 7) |
  (data_link_header.control.primary << 6) |
  (data_link_header.control.frame_count_bit << 5) |
  (data_link_header.control.frame_count_valid << 4) |
  (function_code & 0x0F)
end 

---
-- Calculates the application control byte.
local application_control_calc = function()
	return 
	(application_control.FIR << 7) |
	(application_control.FIN << 6) |
	(application_control.CON << 5) |
	(application_control.UNS << 4) |
	(application_control.SEQ & 0x0F)
end

---
-- Calculates the transport byte.
local transport_control_calc = function()
	return 
	(transport_header.FIR << 7) |
	(transport_header.FIN << 6) |
	(transport_header.SEQ & 0x0F) 
end 
 
---
-- Calculates the CRC-16 for the pakcet, based on OpenDNP3. 
-- Reference: https://github.com/dnp3/opendnp3/blob/c1dc7165a79cc08edbf4b55d2ff4162efb176f92/cpp/lib/src/link/CRC.cpp#L61
-- @param data, header data prior to crc field. 
-- @return result, cyclic value in big endian.
local cyclic_redundancy_check = function(data)
  local crc = 0x0000
  for i = 1, #data do
    local byte = data:byte(i)
    local index = (crc ~ byte) & 0xFF
    crc = ((crc >> 8) ~ dnp3_crc_table[index + 1])
  end
  crc = crc ~ 0xFFFF
  return crc
end

---
-- Switch places for lsb and msb. 
-- Reference: https://cdn.chipkin.com/assets/uploads/imports/resources/DNP3QuickReference.pdf
-- @param data, hex 
-- @returns result, hex
local lsb_msb_switch = function(data)
  local data_hex = string.format("%04x", data)
  local data_BE_hex = data_hex:sub(3, 4) .. data_hex:sub(1, 2)
  local result = tonumber(data_BE_hex, 16)
  return result 
end 

---
-- Validates the range values and orders them correctly in table.
-- @param address_size, either default 0-100, 
-- @return boolean, either true or false depending 
-- @return table, [1] = starting, [2] = end;  range. 
local validate_range = function(address_size)
  local address_range = {}

  if string.find(config.address_size, '-') then
    for value in string.gmatch(config.address_size, "([^-]+)") do
      table.insert(address_range, tonumber(value))
    end
  else
    local single_value = tonumber(config.address_size)
    table.insert(address_range, single_value)
    table.insert(address_range, single_value)
  end

  -- Validate range boundaries
  if address_range[1] < 0 or address_range[2] > 65535 then
    stdnse.print_debug(1, "[!] Address space out of bounds")
    return nil
  elseif address_range[1] > address_range[2] then
    stdnse.print_debug(1, "[!] Starting range is larger than end range")
    return nil
  end
  stdnse.print_debug(1, "[-] Address Range %d-%d", address_range[1], address_range[2])
  return address_range
end

-- Creates the request string.
-- @param control_byte, calculated control byte for the packet config. 
-- @param addr, address to create a packet for.    
-- @return packed request string
local request_link_string = function(control_byte, addr)

  switched_addr = lsb_msb_switch(addr) 

  stdnse.print_debug(1, "[-] Addr LSB/MSB: %s", stdnse.tohex(switched_addr))

  local request_string =  
  string.pack(">I2", data_link_header.start) ..
  string.pack(">B", data_link_header.length) .. 
  string.pack(">B", control_byte) ..
  string.pack(">I2", switched_addr) ..
  string.pack(">I2", data_link_header.source)

  local crc_value = cyclic_redundancy_check(request_string)
  request_string = request_string .. string.pack(">I2", lsb_msb_switch(crc_value))

  stdnse.print_debug(1, "[-] Request Packet: %s", stdnse.tohex(request_string))
  
  return request_string
end

---
-- Takes whatever the response it and parses it according to expected response. 
-- @param data_response, data_response packet from comm.exchange. 
-- @returns output_table, table with the parsed output.
local parse_data_link_response = function(data_response, result)
	
	local control_code = control_codes[string.unpack("B", data_response, 4)]

	result["Source Address"] 		= string.unpack("B", data_response, 7)
	result["Destination Address"] 	= string.unpack("B", data_response, 5)
	result["Control Code"] 			= control_code
	return result
end

---
-- Sends a cold restart command.
-- @param addr, current DNP3 Active address. 
-- @returns chaos (connection_status, data_response), return status and value from sending package. 
local cold_restart = function(host, port, addr)

	local cold_restart_package = ""
	
	-- Data link layer 
	local control_byte = data_link_control_calc(data_link_header.function_codes.UNCONFIRMED_USER_DATA)
	local data_link_header = request_link_string(control_byte, addr)
	local data_link_header_crc = cyclic_redundancy_check(data_link_header)
	
	cold_restart_package = cold_restart_package .. data_link_header .. string.pack("<I2", data_link_header_crc)
	stdnse.print_debug(1, "[-] Cold Restart (Data Link) 1: %s", cold_restart_package)

	-- Application Header & Transport 
	local transport_byte = transport_control_calc()
	local application_control = application_control_calc()
	local cold_restart_function_code = function_codes.cold_restart
	
	local application_header = transport_byte .. application_control .. cold_restart_function_code

	local application_header_crc = cyclic_redundancy_check(application_header)
	
	cold_restart_package = cold_restart_package .. application_header.. string.pack("<I2", application_header_crc)
	stdnse.print_debug(1, "[-] Cold Restart (Data Link & Application Header) 2: %s", cold_restart_package)

	-- Send packet, chaos errupts! 
	local connection_status, data_response = comm.exchange(host, port, cold_restart_package, config.timeout)
	stdnse.print_debug(1, "[-] Response: %s", data_response)

	return connection_status, data_response 
end 

---
-- @param host, currently scanned host. 
-- @param port, always, 20000 (DNP3). 
-- @return returns a table with parsed return data. 
action = function(host, port)

  -- return output
  local result = {}

  -- Calculate the control byte.
  -- Prefer to do it dynamically, easier to configure changes. 
  local control_byte = data_link_control_calc(data_link_header.function_codes.REQUEST_LINK_STATUS)
  stdnse.print_debug(1, "[-] Control Byte value: %s", control_byte)

  -- Verify Address Range 
  local address_range = validate_range(config.address_size)
  if not address_range then
    return nil
  end
	
  -- Compound the request into one packet. 
  -- WARNING: Some slower devices can't parse large packets!
  if config.slow == "false" then
    local request_packet = ""

    for addr = address_range[1], address_range[2] do
      stdnse.print_debug(1, "[-] Current address: %d", addr)

      local data_link_string_tmp = request_link_string(control_byte, addr)
      if data_link_string_tmp == nil then
        stdnse.print_debug(1, "[!] Data link request function returned nil")
        return nil
      end

      request_packet = request_packet .. data_link_string_tmp
    end

    -- Send packet
    local connection_status, data_response = comm.exchange(host, port, request_packet, config.timeout)
		
    if connection_status == false then
      return nil
    else
			if ( #data_response > 9 ) then  
				stdnse.print_debug(1, "[-] Response Data: %s", stdnse.tohex(data_response))
				result = parse_data_link_response(data_response, result)
				
				-- Cold restart to the found active address. 
				if config.bomb == "true" then 
					local status, data = cold_restart(host, port, result["Source Address"])
				end 
			end
		end

  -- Safer for slower devices (but much slower)
  elseif config.slow == "true" then
    for addr = address_range[1], address_range[2] do
      stdnse.print_debug(1, "[-] Current address: %d", addr)

      local request_packet = request_link_string(control_byte, addr)
      if request_packet == nil then
        stdnse.print_debug(1, "[!] Data link request function returned nil")
        return nil
      end

      -- Send packet
      local connection_status, data_response = comm.exchange(host, port, request_packet, config.timeout)
      if connection_status == false then
        stdnse.print_debug(1, "[!] Connection failed for address: %d", addr)
        return nil
      else
	    if ( #data_response > 9 ) then  
				stdnse.print_debug(1, "[-] Response Data: %s", stdnse.tohex(data_response))
				result = parse_data_link_response(data_response, result)
				return result
	    end
      end
    end
  end
  return result
end 
