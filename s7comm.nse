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
-- @args 
-- @args
-- 
-- @output
-- 
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
    header_id              = 0x32,       -- Protocol ID; always 0x32 for S7 communication
    header_job_request     = 0x07,       -- Client request
    header_redundancy      = 0x0000,     -- 2 bytes, usually 0
    header_pdu_ref         = 0x000000,   -- Transaction ID; can be 0. Helps keeping track of packets. 
    header_param_len       = 0x08,       -- Length of the parameters in bytes
    header_data_len        = 0x00,       -- Length of the data section; 0 if no data in request

    function_group         = 0x01,       -- Job type message
    para_head              = 0x12,       -- Read variable (SZL)
    item_len_spec_type     = 0x0411,     -- S7ANY specifier
    syntax_id              = 0x44,       -- SZL read confirmation
    szl_id                 = 0x0100,     -- Module ID of the diagnostic buffer
    szl_index              = 0xff09,     -- Index of elements in SZL list

    payload_function_code  = 0xf0,       -- Function code for payload (Job request)
    payload_number_items   = 0x00,       -- Number of items requested
    payload_item_length    = 0x0001,     -- Length of each item
    payload_additional     = 0x0000,     -- Any other payload flags or reserved bytes.
}

--
local JobParameters = {
    reserved                        = 0x00,     -- Always 0x00
    number_of_items                 = 0x01,     -- Number of items being accessed
    variable_specification          = 0x12,     -- Data Blocks, Inputs, Outputs, Merker 
    return_message_specification    = 0x13,
    function_parameter_block        = 0x16,
    block_parameter_specification   = 0x17,
    addressing_mode                 = 0x04,     -- Syntax ID; 0x04 = S7 symbolic addressing
    transport_size                  = 0x11,     -- 0x11 = BYTE/CHAR/WORD access (ANY)
    data_block                      = 0x4401,   -- DB number in big-endian (e.g., DB65 = 0x4401)
    address_offset                  = 0x0004,   -- Offset in bits from beginning of DB
    request_data_len                = 0x001C    -- Numbers of bytes to read/write
}

-- Quick check to determine service running on port is iso-tsap (s7comm)
portrule = shortport.port_or_service(Config.portNumber, "iso-tsap")

-- Takes out the phone book and starts to call the S7 server. 
-- @param host, Current target host
-- @param port, Current target port
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

-- 
-- @param socket, Opened socket for communication
-- @param message, Hexmessage that you want to send
-- @bytes 
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

-- Setup TP4 connection 
-- @param socket, Opened socket for communication
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

-- Setup ROSE Control (Remote Operation Service Element)
-- @param socket, Opened socket for communication
local rosctr_session = function (socket)

    -- COTP header
    local cotp_header   = string.pack(">BBB", COTP.len, COTP.type_dt, COTP.eot)

    -- S7Comm header
    local s7_header     = string.pack(">BBHI3BB",
            S7.header_id,
            S7.header_job_request,
            S7.header_redundancy,
            S7.header_pdu_ref,
            S7.header_param_len,
            S7.header_data_len
        )

    -- S7Comm parameters ( defining data type request )
    local s7_parameter  = string.pack(">BBHBHH",
            S7.function_group,
            S7.para_head,
            S7.item_len_spec_type,
            S7.syntax_id,
            S7.szl_id,
            S7.szl_index
        )

    -- 
    local s7_data = string.pack(">BBHH",
            S7.payload_function_code,
            S7.payload_number_items,
            S7.payload_item_length,
            S7.payload_additional
        )

    local cotp_packet   = cotp_header .. s7_header .. s7_parameter .. s7_data
    local total_len     = 4 + #cotp_packet
    local tpkt_packet   = string.pack(">BBH", TPKT.version, TPKT.reserved, total_len) .. cotp_packet
    local hex_packet    = stdnse.tohex(tpkt_packet)

    stdnse.print_debug(1, "ROSCTR Packet: %s", hex_packet)

    local response, response_status = call(socket, tpkt_packet, 6)

    return response_status
end
-- 
-- @param host, Current target host
-- @param port, Current target port
action = function(host, port)

    -- Lock in and dial!
    local socket = assert(dial(host, port), "Failed to connect")

    -- Setup required sessions, written with assert to avoid to many lengthy false/true checks. 
    local cotp_response = assert(cotp_session(socket))

    local rosctr_response = assert(rosctr_session(socket))

end