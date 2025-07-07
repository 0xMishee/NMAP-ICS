local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"
local table     = require "table"
local nmap      = require "nmap"

description = [[
This script is primarily designed for scanning and querying devices that communicate using the S7Comm protocol. 
It builds upon the existing script bundled with Nmap, as well as the PLCScan tool by Positive Research (https://code.google.com/archive/p/plcscan/).
The secondary objective is to create an easy-to-modify script that can be adapted for various other purposes, 
with a clear and straightforward setup of the involved protocols for better readability and understanding.
]]

author = "Martin Jakobsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "brute", "intrusive"}

---
-- @usage
-- nmap --script s7comm.nse --script-args=<arguments> -p 102 <target/s>
-- 
-- @args portnumber     - incase portnumber isn't standard 102.
-- @args timeout        - Change timeout otherwise it defaults to 1000.
-- 
-- @output
-- PORT    STATE SERVICE  REASON
-- 102/tcp open  iso-tsap syn-ack ttl 64
-- | s7comm: 
-- |   Module: 6ES7 315-2EH14-0AB0 
-- |   Basic Hardware: 6ES7 315-2EH14-0AB0 
-- |   Version: 3.2.6
-- |   Automation System Name: SNAP7-SERVER
-- |   Module Type: CPU 315-2 PN/DP
-- |   Plant Identification: 
-- |   Copyright: Original Siemens Equipment
-- |_  Serial Number: S C-C2UR28922012
-- 

-- 
local Config = {
    portnumber      = stdnse.get_script_args('s7comm.port') or 102,         --
    timeout         = stdnse.get_script_args('s7comm.timeout') or 1000,     --

}

-- Headers for TPKT, len is calculated dynamically and thus not here. 
local TPKT = {
    version    = 0x03,       -- always 0x03
    reserved   = 0x00,       -- always 0x00
}

-- Connection oriented transport protocol 
local COTP = {

    headers = {},
    tsap    = {},
    tpdu    = {},

    -- Headers
    len                = 0x11,       -- Length after this byte; needed to be defined manually before. Only used for CR.
    type_dt            = 0xF0,       -- Data Transfer TPDU
    type_cr            = 0xE0,       -- Connection Request TPDU
    eot                = 0x80,       -- End Of Transmission bit (used in DT)
    reserved           = 0x00,       -- Reserved, typically 0x00, functions as padding
    src_ref            = 0x00,       -- Source Reference
    dst_ref            = 0x00,       -- Destination Reference
    class              = 0x14,       -- Class 0 (flow control on)

    -- Calling identifier 
    tsap_calling_code  = 0xC1,       -- Calling who
    tsap_calling_len   = 0x02,       -- TSAP length
    tsap_calling_pg_pc = 0x0100,     -- PG/PC device

    -- Identifier for whom am I wish to call
    tsap_called_code   = 0xC2,       -- Called
    tsap_called_len    = 0x02,       -- TSAP length
    tsap_called_pg_pc  = 0x0102,     -- PG/PC device

    tpdu_size_code     = 0xC0,       -- code
    tpdu_size_len      = 0x01,       -- length
    tpdu_size_val      = 0x0A,       -- 0x0A = 1024 bytes
}

--
local S7 = {

    headers     = {},
    parameter   = {},
    data        = {},

    header_id               = 0x32,       -- Protocol ID; always 0x32 for S7 communication
    header_job_request      = 0x01,       -- Job
    header_read_request     = 0x07,       -- Read
    header_reserved         = 0x0000,     -- Always set to 0x0000
    header_pdu_ref          = 0x0000,     -- Transaction ID; can be 0. Helps keeping track of packets, incremental.
    header_param_len        = 0x0008,     -- Length of the parameters in bytes

    -- Data lengths
    header_data_len_nd      = 0x0000,     -- Length of the data section; 0 if no data in request.
    header_data_len_rd      = 0x0008,     -- Reading SZL 


    -- Parameters
    -- S7 functions
    parameter_func_sc           = 0xf0,       -- Setup Communication function code
    parameter_func_cpu          = 0x00,       -- Prepares to querying CPU information

    parameter_item_count        = 0x01,
    parameter_variable_spec     = 0x12,
    parameter_len_address_spec  = 0x04,
    parameter_syntax_id         = 0x11,
    parameter_type_request_cpu  = 0x44,
    parameter_sub_func_r_szl    = 0x01,
    parameter_sequence_nr       = 0x00,


    --
    parameter_reserved          = 0x00,       -- Reserved, usually 0.
    parameter_amq_calling       = 0x0001,     -- AMQ Calling (PDU reference from sender)
    parameter_amq_called        = 0x0001,     -- AMQ Called (PDU reference from receiver)
    parameter_pdu_size          = 0x01e0,     -- PDU size, determines how many concurrent sessions can be made; 112, 240, 480, 960 or 1920 bytes.

    -- Data
    data_return_code                = 0xff,
    data_transport_size             = 0x09,
    data_len                        = 0x0004,
    data_type_diag_cpu_mod_id       = 0x0011, -- Module identification
    data_type_diag_cpu_comp_id      = 0x001c, -- Component identification
    data_szl_index                  = 0x0001,


}

---
-- Quick check to determine service running on port is iso-tsap (s7comm)
portrule = shortport.port_or_service(Config.portNumber, "iso-tsap")

---
-- Takes out the phone book and starts to call the S7 server. 
-- @param host, Current target host
-- @param port, Current target port
-- @return socket, Returns an opened socket.
local dial = function (host, port)

    local socket = nmap.new_socket()
    local status, error = socket:connect(host, port)

    -- No point talking if you're not answering
    if not status then
        stdnse.print_debug(1, "Failed: %s", error)
        socket:close(error)
        return nil
    else 
        stdnse.print_debug(1, "Status: %s", status)
    end

    return socket
end

---
-- @param socket, Opened socket for communication
-- @param message, Hexmessage that you want to send
-- @bytes 
-- @return response, response_status, Returns hexstring from the PLC.
local call = function (socket, message ,bytes)

    local send_status, send_error = socket:send(message)
    if(send_status == false) then
        stdnse.print_debug(1, "Error while trying to send: %s", send_error)
        return nil
    end

    local response_status, response = socket:receive_bytes(bytes)
    if type(response) == "string" then
        local hex_response = stdnse.tohex(response)
        stdnse.print_debug(1, "Received bytes: %s %s", hex_response, response_status)
    else
        stdnse.print_debug(1, "Failed to receive bytes or got non-string response: %s", tostring(response))
    end

    return response, response_status
end

---
-- Setup TP4 connection 
-- @param socket, Opened socket for communication
-- @return response_status, True or False if the sessions was established or not.
local cotp_session = function (socket)

    -- COTP header
    local cotp_header   = string.pack(">BBBBBB", COTP.len, COTP.type_cr, COTP.reserved, COTP.src_ref, COTP.dst_ref, COTP.class)

    -- COTP parameters
    local cotp_size     = string.pack(">BBB", COTP.tpdu_size_code, COTP.tpdu_size_len, COTP.tpdu_size_val)
    local cotp_calling  = string.pack(">BBBH", COTP.reserved, COTP. tsap_calling_code, COTP.tsap_calling_len, COTP.tsap_calling_pg_pc)
    local cotp_called   = string.pack(">BBH", COTP.tsap_called_code, COTP.tsap_called_len, COTP.tsap_called_pg_pc)

    -- Assembly!
    local cotp_packet   = cotp_header .. cotp_calling .. cotp_called .. cotp_size

    local total_len     = 4 + #cotp_packet
    local tpkt_packet   = string.pack(">BBH", TPKT.version, TPKT.reserved, total_len) .. cotp_packet

    local hex_packet    = stdnse.tohex(tpkt_packet)
    stdnse.print_debug(1, "COTP Connection Request Packet: %s", hex_packet)

    -- Calling! 
    local response, response_status = call(socket, tpkt_packet, 6)

    return response_status
end

---
-- Setup ROSE Control (Remote Operation Service Element)
-- @param socket, Opened socket for communication
-- @return response_status, True or False if the sessions was established or not.
local rosctr_session = function (socket)

    -- COTP header
    local cotp_header   = string.pack(">BBB", COTP.len, COTP.type_dt, COTP.eot)

    -- S7Comm header
    local s7_header     = string.pack(">BBHHHH",
            S7.header_id,
            S7.header_job_request,
            S7.header_reserved,
            S7.header_pdu_ref,
            S7.header_param_len,
            S7.header_data_len_nd
        )

    -- S7Comm parameters ( defining data type request )
    local s7_parameter  = string.pack(">BBHHH",
            S7.parameter_func_sc,
            S7.parameter_reserved,
            S7.parameter_amq_calling,
            S7.parameter_amq_called,
            S7.parameter_pdu_size
        )

    local cotp_packet   = cotp_header .. s7_header .. s7_parameter
    local total_len     = 4 + #cotp_packet
    local tpkt_packet   = string.pack(">BBH", TPKT.version, TPKT.reserved, total_len) .. cotp_packet
    local hex_packet    = stdnse.tohex(tpkt_packet)

    local response, response_status = call(socket, tpkt_packet, 6)

    stdnse.print_debug(1, "ROSCTR Sending: %s", hex_packet)
    stdnse.print_debug(1, "ROSCTR Received: %s", response)

    return response_status
end

---
-- Reads diagnostic data for both the module and component calls.
-- @param socket, Opened socket for communication
-- @return response_component, response_module, Returns hexstrings from both calls.
local read_szl = function (socket)


    local cotp_header   = string.pack(">BBB", COTP.len, COTP.type_dt, COTP.eot)

    local s7_header     = string.pack(">BBHHHH",
                        S7.header_id,
                        S7.header_read_request,
                        S7.header_reserved,
                        S7.header_pdu_ref,
                        S7.header_param_len,
                        S7.header_data_len_rd
    )

    local s7_parameter  = string.pack(">BBBBBBBB",
                        S7.parameter_func_cpu,
                        S7.parameter_item_count,
                        S7.parameter_variable_spec,
                        S7.parameter_len_address_spec,
                        S7.parameter_syntax_id,
                        S7.parameter_type_request_cpu,
                        S7.parameter_sub_func_r_szl,
                        S7.parameter_sequence_nr
    )

    local s7_data_module = string.pack(">BBHHH",
                        S7.data_return_code,
                        S7.data_transport_size,
                        S7.data_len,
                        S7.data_type_diag_cpu_mod_id,
                        S7.data_szl_index
    )

    local s7_data_component = string.pack(">BBHHH",
                        S7.data_return_code,
                        S7.data_transport_size,
                        S7.data_len,
                        S7.data_type_diag_cpu_comp_id,
                        S7.data_szl_index
    )

    local cotp_packet_module        = cotp_header .. s7_header .. s7_parameter .. s7_data_module
    local cotp_packet_component     = cotp_header .. s7_header .. s7_parameter .. s7_data_component

    local total_len_module     = 4 + #cotp_packet_module
    local tpkt_packet_module   = string.pack(">BBH", TPKT.version, TPKT.reserved, total_len_module) .. cotp_packet_module

    local total_len_component     = 4 + #cotp_packet_component
    local tpkt_packet_component   = string.pack(">BBH", TPKT.version, TPKT.reserved, total_len_component) .. cotp_packet_component

    local response_module, response_status_module = call(socket, tpkt_packet_module, 6)
    local response_component, response_status_component = call(socket, tpkt_packet_component, 6)

    stdnse.print_debug(1, "SZL Module Sending: %s", stdnse.tohex(tpkt_packet_module))
    stdnse.print_debug(1, "SZL Module Received: %s", stdnse.tohex(response_module))

    stdnse.print_debug(1, "SZL Component Sending: %s", stdnse.tohex(tpkt_packet_component))
    stdnse.print_debug(1, "SZL Component Received: %s", stdnse.tohex(response_component))

    return response_component, response_module

end

---
-- Takes response from scan and turns it into human readable format.
-- @param response, Translates response hex string.
-- @return discombobulate, Table to display with diagnostics data.
local transponster = function(szl_component, szl_module, discombobulate)


    -- Module Translation
    if #szl_module > 126 then
        local szl_v_1, szl_v_2, szl_v_3 = string.unpack("BBB", szl_module, 123)

        discombobulate['Module'] = string.unpack("z", szl_module, 44)
        discombobulate['Basic Hardware'] = string.unpack("z", szl_module, 72)
        discombobulate['Version'] = table.concat({szl_v_1, szl_v_2, szl_v_3}, '.')
    end

    -- Component Translation
    local offset = (string.byte(szl_component, 31) ~= 0x1c) and 4 or 0
    stdnse.print_debug(1, "Offset: %d", offset)

    if #szl_component > 40 + offset then
        discombobulate['Automation System Name'] = string.unpack("z", szl_component, 40 + offset)
    end

    if #szl_component > 74 + offset then
        discombobulate['Module Type'] =string.unpack("z", szl_component, 74 + offset)
    end

    if #szl_component > 108 + offset then
        discombobulate['Plant Identification'] = string.unpack("z", szl_component, 108 + offset)
    end

    if #szl_component > 142 + offset then
        discombobulate['Copyright'] = string.unpack("z", szl_component, 142 + offset)
    end

    if #szl_component > 176 + offset then
        discombobulate['Serial Number'] = string.unpack("z", szl_component, 176 + offset)
    end

    return discombobulate
end


---
-- @param host, Current target host
-- @param port, Current target port
-- @return discombobulate, Returns table populated with diagnostics information.
action = function(host, port)

    -- Lock in and dial!
    local socket = assert(dial(host, port), "Failed to connect")

    -- Setup required sessions, written with assert to avoid to many lengthy false/true checks. 
    local cotp_response = assert(cotp_session(socket))

    local rosctr_response = assert(rosctr_session(socket))

    -- Fetch Diagnostics data from PLC
    local read_szl_component, read_szl_module = assert(read_szl(socket))

    -- Create table and send received data to be parsed.
    local discombobulate = stdnse.output_table()
    discombobulate = transponster(read_szl_component, read_szl_module, discombobulate)

    return discombobulate
end
