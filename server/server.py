#!/usr/bin/env python
from progress.bar import ChargingBar
from PyInquirer import prompt
import keyboard
import time
import struct
import socket
import os
import sys
from math import ceil

Devices = {}
RetransmitDevices = {}
DeviceNames = []
Listening = True
Socket = None

MYPORT = 20001
MYGROUP_4 = '232.10.11.12'
MYTTL = 1 # Increase to reach other networks

keyboard.on_press_key("u", lambda _:Update())
keyboard.on_press_key("r", lambda _:Retransmit())

def GetFirmwareSize(filename):
    st = os.stat(filename)
    return st.st_size

def Update():
    global Listening, Socket
    Listening = False
    try:
        Socket.shutdown(socket.SHUT_RDWR)
        Socket.close()
    except:
        pass

def Retransmit():
    global Listening, Socket
    Listening = False
    try:
        Socket.shutdown(socket.SHUT_RDWR)
        Socket.close()
    except:
        pass
  
def ChoiceDevices():
    global DeviceNames

    if len(DeviceNames) > 0:
    	widget = [
    	{
    	    'type':'checkbox',
    	    'name':'devices',
    	    'message':'Please select the devices whose operating system you want to update.',
    	    'choices': DeviceNames
    	}
    	]
    	result = prompt(widget)
    	UpdateAdvertisement(result["devices"])
    else:
    	print("There is no joined devices")
    	sys.exit()

def UpdateAdvertisement(DeviceList):
    print("Start sending update command to the selected devices...")
    addrinfo = socket.getaddrinfo(MYGROUP_4, None)[0]
    s = socket.socket(addrinfo[0], socket.SOCK_DGRAM)
    ttl_bin = struct.pack('@i', MYTTL)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)
        
    for Device in DeviceList:
        s.sendto(b'NewFirmware', Devices[Device])
    
    print("Start updating...")
    
    UpdateRoutine()

def UpdateRoutine():
    
    addrinfo = socket.getaddrinfo(MYGROUP_4, None)[0]
   
    Socket = socket.socket(addrinfo[0], socket.SOCK_DGRAM)

    # Set Time-to-live (optional)
    ttl_bin = struct.pack('@i', MYTTL)
    Socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)

    SecureFirmwareName = 'SecureFirmware.bin'
    SecureFirmwareLen = GetFirmwareSize(SecureFirmwareName)
    print("Firmware file has load.")

    ChunkSize = 1012
    ChunkCount = ceil( SecureFirmwareLen / ChunkSize )
    

    SecureFirmwareFile = open(SecureFirmwareName,"rb")
    print("Firmware file size is %s bytes" % SecureFirmwareLen)

    datafile = SecureFirmwareFile.read( ChunkSize )

    Progress = ChargingBar('Updating', max=ChunkCount, suffix = '%(index)d/%(max)d [%(percent)d%%]')

    while datafile:
        Socket.sendto(datafile, (addrinfo[4][0], MYPORT))
        datafile = SecureFirmwareFile.read( ChunkSize )
        Progress.next( )
        time.sleep(0.08)
        #time.sleep(0.08)
    print("\nUpdate Done!")


def NodeJoin(DeviceName, DeviceInfo):
    global Devices, DeviceNames
    Devices[DeviceName] = DeviceInfo
    DeviceNames.append({'name':DeviceName})
    print (" %s)\t%s\t\t%s"  % (len(Devices),DeviceName, DeviceInfo)) 
    return 

def RetransmitNodeJoin(DeviceName, DeviceInfo,RetransmitIndex):
    global RetransmitDevices
    RetransmitDevices[DeviceName] = (DeviceInfo,RetransmitIndex)
    print (" %s)\t%s\t\t%s\t%s"  % (len(Devices),DeviceName,RetransmitIndex, DeviceInfo)) 
    return 

def Server():
    global Devices, Listening, Socket
    # Look up multicast group address in name server and find out IP version
    addrinfo = socket.getaddrinfo(MYGROUP_4, None)[0]

    # Create a socket
    Socket = socket.socket(addrinfo[0], socket.SOCK_DGRAM)

    # Allow multiple copies of this program on one machine
    # (not strictly needed)
    Socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind it to the port
    Socket.bind(('', MYPORT))

    group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
    # Join group
    mreq = group_bin + struct.pack('=I', socket.INADDR_ANY)
    Socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    # Loop, printing any data we receive
    DeviceNamesPrefix = "ESP32_"
    UplinkIndicator = "alive"

    print( "Server has started listening...")
    print( "Press u for updating appeared devices.")
    print( "Device list(updating...):" )
    print (" Number\tName\t\tInfo")
    while Listening:
        try:
            data, DeviceInfo = Socket.recvfrom(100)
            DeviceName = data.decode('ascii').split( ":")[0]
            DeviceData = data.decode('ascii').split( ":")[1].strip()
            while data[-1:] == '\0': data = data[:-1] # Strip trailing \0's
            if DeviceData == UplinkIndicator and DeviceNamesPrefix in DeviceName and DeviceName not in Devices:
                NodeJoin(DeviceName, DeviceInfo)
        except:
            pass


def RetransmitFirmware(rDevices):
    global RetransmitDevices
    
    addrinfo = socket.getaddrinfo(MYGROUP_4, None)[0]
   
    Socket = socket.socket(addrinfo[0], socket.SOCK_DGRAM)

    # Set Time-to-live (optional)
    ttl_bin = struct.pack('@i', MYTTL)
    Socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)

    SecureFirmwareName = 'SecureFirmware.bin'
    SecureFirmwareLen = GetFirmwareSize(SecureFirmwareName)
    print("Firmware file has load.")

    ChunkSize = 1012
    ChunkCount = ceil( SecureFirmwareLen / ChunkSize )
    

    SecureFirmwareFile = open(SecureFirmwareName,"rb")
    print("Firmware file size is %s bytes" % SecureFirmwareLen)


    datafile = SecureFirmwareFile.read( ChunkSize )
    ChunkedSecureFirmware = []
    while datafile:
        ChunkedSecureFirmware.append(datafile)
        datafile = SecureFirmwareFile.read( ChunkSize )

    for _device in rDevices:
    	Progress = ChargingBar('Retransmiting to ' + _device , max=ChunkCount - int(RetransmitDevices[_device][1]), suffix = '%(index)d/%(max)d [%(percent)d%%]')

    	for index in range( int(RetransmitDevices[_device][1]), ChunkCount):
                Socket.sendto(ChunkedSecureFirmware[index], RetransmitDevices[_device][0])
                Progress.next( )
                time.sleep(0.08)
    print("\nRetransmiting Done!")


def ChoiceRetransmitDevices():
    global RetransmitDevices
    if len(RetransmitDevices) > 0:
    	_devices = [ {'name': name} for name in list(RetransmitDevices.keys())]
    	widget = [
    	{
    	    'type':'checkbox',
    	    'name':'devices',
    	    'message':'Please select the devices whose operating system you want to update agan.',
    	    'choices': _devices
    	}
    	]
    	result = prompt(widget)
    	RetransmitFirmware(result["devices"])
    else:
    	print("There is no joined devices")
    	sys.exit()

def Verify():
    global Devices, Listening, Socket
    global RetransmitDevices
    Listening = True
    # Look up multicast group address in name server and find out IP version
    addrinfo = socket.getaddrinfo(MYGROUP_4, None)[0]

    # Create a socket
    Socket = socket.socket(addrinfo[0], socket.SOCK_DGRAM)

    # Allow multiple copies of this program on one machine
    # (not strictly needed)
    Socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind it to the port
    Socket.bind(('', MYPORT))

    group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
    # Join group
    mreq = group_bin + struct.pack('=I', socket.INADDR_ANY)
    Socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    # Loop, printing any data we receive
    DeviceNamesPrefix = "ESP32_"
    RetransmitIndicator = "ret"
    print( "Server has started vrifing...")
    print( "Press r for retransmit firmware to the appeared devices.")
    print( "Device list(updating...):" )
    print (" Number\tName\t\tIndex\tInfo")
    while Listening:
        try:
            data, DeviceInfo = Socket.recvfrom(100)
            DeviceName = data.decode('ascii').split( ":")[0]
            DeviceData = data.decode('ascii').split( ":")[1].strip()
            RetransmitIndex = DeviceData.replace(RetransmitIndicator,'')
            while data[-1:] == '\0': data = data[:-1] # Strip trailing \0's
            if RetransmitIndicator in DeviceData and DeviceName in Devices and DeviceName not in RetransmitDevices :
                RetransmitNodeJoin(DeviceName, DeviceInfo, RetransmitIndex)
        except:
            pass

#Firmware encrypting section
import http.server as SimpleHTTPServer
import socketserver
from math import ceil
from mbedtls import hmac
from mbedtls import hashlib
from mbedtls import cipher
import logging

lastPacketSize = 0
lastPacketPadd = 0

def ChunkFirmware (Firmware,ChunkSize):
  global lastPacketSize
  global lastPacketPadd
  ChunkedFirmware = [ Firmware[i:i+ChunkSize] for i in range(0, len(Firmware), ChunkSize) ]

  lastPacketSize = len(ChunkedFirmware[-1])
  print( lastPacketSize )
  lastPacketPadd = lastPacketSize % 16
  print( lastPacketPadd )

  if( lastPacketPadd != 0 ):
    ChunkedFirmware[-1] += (0).to_bytes(lastPacketPadd, byteorder='big')

  return ChunkedFirmware

def encrypt(Chunk, KSW, IV):
  c = cipher.AES.new(KSW, cipher.MODE_GCM, IV,b'')
  enc = c.encrypt(Chunk)
  return enc[0]

def EncryptFirmware (ChunkedFirmware, KSW, IV):
  EncryptedFirmware = [ encrypt(Chunk, KSW, IV) for Chunk in ChunkedFirmware]
  return EncryptedFirmware

def Sha256(Input):
  Hash = hashlib.sha256()
  Hash.update(Input)
  return Hash.digest()

def ReorderChunks(Chunks):
  return Chunks[::-1]

def ComputeHashs(EncryptedFirmware):
  LastIndex = len( EncryptedFirmware )
  Hashs= [None] * LastIndex
  Hashs[LastIndex - 1] = Sha256( (LastIndex - 1).to_bytes(4, byteorder='big') + EncryptedFirmware[-1] )
  print("hii",LastIndex - 1,len(Hashs),len(EncryptedFirmware))
  for Index in list(range(LastIndex - 2, -1, -1)):
    Hashs[Index] = Sha256( (Index).to_bytes(4, byteorder='big') + EncryptedFirmware[Index] + Hashs[Index + 1] ) 
  return Hashs

def MACI(IKSW, Index, EI, HASHIMINUS):
  c =  hmac.new(IKSW, digestmod="sha256")
  if HASHIMINUS:
    c.update(bytes((Index).to_bytes(4, byteorder='big') + EI + HASHIMINUS))
  else:
    #last index
    c.update(bytes((Index).to_bytes(4, byteorder='big') + EI ))
  return c.digest()

def OpenFirmWare( FirmwareName ):
  f = open(FirmwareName, 'rb')
  FirmWare = f.read()
  f.close()
  return FirmWare


if __name__ == '__main__':
    IKSW = b'gv4rrcQoL3PWZG8V'
    #128 bit AES key
    KSW = b'uaRNrZKutHtZoplzuaRNrZKutHtZoplz'
    IV = b's0fGiJWHN5FLmdd9'
    ChunkSize = 944
    ChunkCount = 0
    FirmwareName = 'hello-world.bin'
    Firmware = OpenFirmWare(FirmwareName)

    ChunkCount = ceil(len(Firmware)/ ChunkSize)
    FirmwareLen = len(Firmware)
    ChunkedFirmware = ChunkFirmware (Firmware,ChunkSize)
    FirstChunkHash = Sha256(ChunkedFirmware[0])
    EncryptFirmware = EncryptFirmware (ChunkedFirmware, KSW, IV)
    ChunkHashs = ComputeHashs(EncryptFirmware)


    ChunkCount = len( EncryptFirmware )
    ChunkMACS = [None] * ChunkCount
    Packets = [None] * ChunkCount

    ChunkMACS[ChunkCount - 1] = MACI(IKSW,ChunkCount - 1,EncryptFirmware[ChunkCount - 1],None)
    print("lastmac", "{0x" + ChunkMACS[ChunkCount - 1] .hex().upper().replace(' ',',0x') + "}")
    print("lastenc", "{0x" + EncryptFirmware[ChunkCount - 1].hex().upper().replace(' ',',0x') + "}")
    Packets[ChunkCount - 1] = (ChunkCount - 1).to_bytes(4, byteorder='big') + EncryptFirmware[ChunkCount - 1] + ChunkMACS[ChunkCount - 1]

    for Index in list(range(ChunkCount - 2, -1, -1)):
        ChunkMACS[Index] = MACI(IKSW, Index, EncryptFirmware[Index], ChunkHashs[Index + 1])
        Packets[Index] = (Index).to_bytes(4, byteorder='big') + EncryptFirmware[Index] + ChunkHashs[Index +1] + ChunkMACS[Index]

    SecureFirmware = b''.join(Packets)
    SecureFirmwareFile = open("SecureFirmware.bin", "wb")
    SecureFirmwareFile.write(SecureFirmware)
    SecureFirmwareFile.close()

    SecureFirmwareLen = len(SecureFirmware)

    index_offset = 0
    index_length = 4
    enc_offset = index_offset + index_length
    enc_length = len(EncryptFirmware[0])
    hash_offset  = enc_length + enc_offset
    hash_length  = len(ChunkHashs[0])
    mac_offset  = hash_length + hash_offset
    mac_length = len(ChunkMACS[0])
    mac_calculate_offset = index_offset
    mac_calculate_length= hash_length + hash_offset

    print("IKSW", str(IKSW))
    print("KSW", str(KSW))
    print("IV", str(IV))

    print("OriginalFirmwareLen", FirmwareLen)
    print("SecureFirmwareLen", SecureFirmwareLen)
    print("OverHead", (SecureFirmwareLen - FirmwareLen) , "Bytes(", ((SecureFirmwareLen / FirmwareLen) - 1) *100, ")%" )

    print("ChunkSize", str(ChunkSize))
    print("ChunkCount", str(ChunkCount))
    print("Packet_length" , len(Packets[1]))
    print("last Packet_length" , len(Packets[-1]))
    print("last chunk_length" , len(ChunkedFirmware[-1]))
    #print("FirstChunkHash", "{0x" + ChunkHashs[0].hex(' ', -1).upper().replace(' ',',0x') + "}")
    print("FirstChunkHash", "{0x" + ChunkHashs[0].hex().upper().replace(' ',',0x') + "}")
    print("index_offset" , index_offset)
    print("index_length" , index_length)
    print("enc_offset" , enc_offset)
    print("enc_length" , enc_length)
    print("hash_offset" , hash_offset)
    print("hash_length" , hash_length)
    print("mac_offset" , mac_offset)
    print("mac_length" , mac_length)
    print("mac_calculate_offset" , mac_calculate_offset)
    print("mac_calculate_length" , mac_calculate_length)

    Server()
    ChoiceDevices()
    Verify()
    ChoiceRetransmitDevices()
    
