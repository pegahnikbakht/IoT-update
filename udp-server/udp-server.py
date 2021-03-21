#!/usr/bin/env python
from progress.bar import ChargingBar
from PyInquirer import prompt
import keyboard
import time
import struct
import socket
import os
from math import ceil

Devices = {}
DeviceNames = []
Listening = True
Socket = None

MYPORT = 20001
MYGROUP_4 = '232.10.11.12'
MYTTL = 1 # Increase to reach other networks

keyboard.on_press_key("u", lambda _:Update())

def GetFirmwareSize(filename):
    st = os.stat(filename)
    return st.st_size

def Update():
    global Listening, Socket
    Listening = False
    Socket.shutdown(socket.SHUT_RDWR)
    Socket.close()
    
def ChoiceDevices():
    global DeviceNames
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
        time.sleep(0.2)


def NodeJoin(DeviceName, DeviceInfo):
    global Devices, DeviceNames
    Devices[DeviceName] = DeviceInfo
    DeviceNames.append({'name':DeviceName})
    print (" %s)\t%s\t\t%s"  % (len(Devices),DeviceName, DeviceInfo)) 
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


if __name__ == '__main__':
    Server()
    ChoiceDevices()




