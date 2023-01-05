-- Based in ftp-syst.nse and ftp-anon.nse

local stdnse = require "stdnse"
local ftp  = require "ftp"
local shortport = require "shortport"

---
-- @usage
-- nmap -p 21 --script ftp-steal.nse --script-args user=<ftp_user>,pass=<ftp_pass>,dir=<file_directory_path> <ip>
--
-- @args user: Username for user in ftp server
--       pass: Password for user in ftp server
--       dir: When set determines the directory in ftp server where to look for file
--
-- @output
-- PORT   STATE SERVICE REASON
-- 21/tcp open  ftp     syn-ack
-- | ftp-steal: 
-- |   tftp file test
-- |_  password:holi


author = "Tomás Torres"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "auth"}

portrule = shortport.port_or_service({21,990},{"ftp","ftps"})

--- NOTES
-- socket is used to send commands
-- pasv_socket is used to get file information
action = function(host, port)
  local file_name = "user.cfg"

  local socket, code, message, buffer = ftp.connect(host, port)
  if not socket then
    stdnse.debug(1,"Couldn't connect: %s", code or message)
    return nil
  end

-- Authentication
  local username = stdnse.get_script_args("user")
  local password = stdnse.get_script_args("pass")
  local auth_status, auth_code, auth_message = ftp.auth(socket, buffer, username, password)
  if not auth_status then
    if not auth_code then
      stdnse.debug1("got socket error %q.", auth_message)
      return nil
    else
      stdnse.debug1("got code %d %q.", auth_code, auth_message)
      return ("got code %d %q."):format(auth_code, auth_message)
    end
  end

-- Create socket in PASV mode for file transfering
  local pasv_socket, pasv_err = ftp.pasv(socket, buffer)
  if pasv_err then
    stdnse.debug(1, "Error with PASV mode socket: %s",  pasv_err)
  end

-- SEND CWD file directory command
  local dir =  stdnse.get_script_args("dir")
  if dir then
    stdnse.debug(1,"Sending CWD command")
    local cwd_status, cwd_error = socket:send(("CWD %s\r\n"):format(dir))
    if not cwd_status then
      stdnse.debug(1, "CWD %s command error: %s %s ", dir, cwd_status, cwd_error)
      return nil
    end
-- GET CD response
    local cwd_response_code, cwd_response_message = ftp.read_reply(buffer)
    stdnse.debug(1, "CWD response: %s %s",  cwd_response_code, cwd_response_message)
  end

-- GET file transfer command for file name
  stdnse.debug(1,"Sending GET file command")
  local get_status, get_error = socket:send(("RETR %s\r\n"):format(file_name))
  if not get_status then
    stdnse.debug(1, "GET command file error: %s %s", get_status, get_error)
    return nil
  end
-- GET file transfer response
  local get_response_code, get_response_message = ftp.read_reply(buffer)
  if get_response_code and get_response_code ~= 150 then
    stdnse.debug(1, "GET response: %s %s", get_response_code, get_response_message)
    return nil
  end

-- Receive file information through pasv socket
-- Check for keywords in each line
  local lines_list = {"Lines containing keywords:"}
  while true do
    local line_status, line_data = pasv_socket:receive_buf("\r?\n", false)
    if (not line_status and line_data == "EOF") or line_data == "" then
      break
    end
--    stdnse.debug(1, "Data status: %s ",  line_status)
--    stdnse.debug(1, "Data info: %s ",  line_data)
    if not line_status then
      return line_status, line_data
    end
    if string.find(line_data,"password") or string.find(line_data,"tftp") or string.find(line_data,"write") then
      lines_list[#lines_list + 1] = "  " .. line_data
    end
  end

-- GET transfer response
  local get_transfer_code, get_transfer_message = ftp.read_reply(buffer)
  stdnse.debug(1, "Transfer response: %s %s",  get_transfer_code, get_transfer_message)
 
-- Close FTP connection
  ftp.close(socket)
  
  if (#lines_list > 1) then
    return lines_list
  else 
    return nil
  end
end
