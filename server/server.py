import http.server as SimpleHTTPServer
import socketserver
from math import ceil
from mbedtls import hmac
from mbedtls import hashlib
from mbedtls import cipher
import logging


def ChunkFirmware (Firmware,ChunkSize):
  ChunkedFirmware = [ Firmware[i:i+ChunkSize] for i in range(0, len(Firmware), ChunkSize) ]
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
  Hashs = [Sha256( (0).to_bytes(4, byteorder='big') + EncryptedFirmware[0] )]
  for ChunkIndex, Chunk in enumerate(EncryptedFirmware,1):
    Hashs.append( Sha256( (ChunkIndex).to_bytes(4, byteorder='big') + Chunk + Hashs[ ChunkIndex-1 ] ) )
  return Hashs

def MACI(IKSW, Index, EI, HASHIMINUS):
  c =  hmac.new(IKSW, digestmod="sha256")
  if HASHIMINUS:
    c.update(bytes((Index).to_bytes(4, byteorder='big') + EI + HASHIMINUS))
  else:
    #zero index
    c.update(bytes((Index).to_bytes(4, byteorder='big') + EI ))
  return c.digest()

def OpenFirmWare( FirmwareName ):
  f = open(FirmwareName, 'rb')
  FirmWare = f.read()
  f.close()
  return FirmWare



IKSW = b'gv4rrcQoL3PWZG8V'
KSW = b'uaRNrZKutHtZoplz'
IV = b's0fGiJWHN5FLmdd9'
ChunkSize = 956
ChunkCount = 0
FirmwareName = 'hello-world.bin'
Firmware = OpenFirmWare(FirmwareName)
ChunkCount = ceil(len(Firmware)/ ChunkSize)
FirmwareLen = len(Firmware)
ChunkedFirmware = ChunkFirmware (Firmware,ChunkSize)
FirstChunkHash = Sha256(ChunkedFirmware[0])

print("IKSW", str(IKSW))
print("KSW", str(KSW))
print("IV", str(IV))
print("ChunkSize", str(ChunkSize))
print("ChunkCount", str(ChunkCount))
#print("FirstChunkHash", "{0x" + FirstChunkHash.hex(' ', -1).upper().replace(' ',',0x') + "}")

EncryptFirmware = EncryptFirmware (ChunkedFirmware, KSW, IV)
ChunkHashs = ComputeHashs(EncryptFirmware)
print("FirstChunkHash", "{0x" + ChunkHashs[0].hex(' ', -1).upper().replace(' ',',0x') + "}")
ChunkMACS = [MACI(IKSW,0,EncryptFirmware[0],None)]
Packets = [(0).to_bytes(4, byteorder='big') + EncryptFirmware[0] + ChunkHashs[0] + ChunkMACS[0] ]

for Index in range(1 , ChunkCount):
  ChunkMACS.append(MACI(IKSW,Index,EncryptFirmware[Index],ChunkHashs[Index - 1]))
  Packets.append((Index).to_bytes(4, byteorder='big') + EncryptFirmware[Index] + ChunkHashs[Index-1] + ChunkMACS[Index])

SecureFirmware = b''.join(Packets)
SecureFirmwareFile = open("SecureFirmware.bin", "wb")
SecureFirmwareFile.write(SecureFirmware)
SecureFirmwareFile.close()


print("OriginalFirmwareLen", FirmwareLen)
SecureFirmwareLen = len(SecureFirmware)
print("FirmwareLen", SecureFirmwareLen)

print("OverHead", (SecureFirmwareLen - FirmwareLen) , "Bytes(", ((SecureFirmwareLen / FirmwareLen) - 1) *100, ")%" )

Packet_length = len(Packets[1])
#first packet has no hash-1
print("1st Packet_length" , len(Packets[0]))
print("Packet_length" , Packet_length)



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
PORT = 8000

print("SecureFirmwareURL","http://<yourserveraddress>/SecureFirmware.bin" )
class GetHandler(
        SimpleHTTPServer.SimpleHTTPRequestHandler
        ):

    def do_GET(self):
        logging.error(self.headers)
        print(self.client_address)
        SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)


Handler = GetHandler
Handler = GetHandler
httpd = socketserver.TCPServer(("", PORT), Handler)

httpd.serve_forever()


