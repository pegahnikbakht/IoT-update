import socket
import struct
import sys

multicast_group = '232.10.11.12'
server_address = ('', 20001)

# Create the socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind to the server address
sock.bind(server_address)


# Tell the operating system to add the socket to the multicast group
# on all interfaces.
group = socket.inet_aton(multicast_group)
mreq = struct.pack('4sL', group, socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)


file_name='hello-world.bin'
buf = 1024
#s.sendto(file_name,addr)

f=open(file_name,"rb")
data = f.read(buf)

# Receive/send loop
while (data):
    print (sys.stderr, '\nwaiting to receive message' )
    data, address = sock.recvfrom(1024)
    
    print (sys.stderr, 'received %s bytes from %s' % (len(data), address))
    print (sys.stderr, data)

    print (sys.stderr, 'sending data to', address) 
    sock.sendto(data, address)
    data = f.read(buf)
