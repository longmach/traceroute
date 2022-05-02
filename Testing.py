
# Adapted from companion material available for the textbook Computer Networking: A Top-Down Approach, 6th Edition
# Kurose & Ross ©2013

from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT  = 2.0
TRIES    = 2

def checksum(string):
	csum = 0
	countTo = (len(string) // 2) * 2

	count = 0
	while count < countTo:
		thisVal = string[count+1] * 256 + string[count]
		csum = csum + thisVal
		csum = csum & 0xffffffff
		count = count + 2

	if countTo < len(string):
		csum = csum + string[len(string) - 1]
		csum = csum & 0xffffffff

	csum = (csum >> 16) + (csum & 0xffff)
	csum = csum + (csum >> 16)
	answer = ~csum
	answer = answer & 0xffff
	answer = answer >> 8 | (answer << 8 & 0xff00)
	return answer

def build_packet(data_size):
	# adapted from: https://stackoverflow.com/questions/19897209/troubleshooting-typeerror-ord-expected-string-of-length-1-but-int-found
	# First, make the header of the packet, then append the checksum to the header,
	# then finally append the data
	id = os.getpid()
	header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, id, 1)
	data = struct.pack('d', time.time())
	myChecksum = checksum(header + data)
	myChecksum = htons(myChecksum)
	header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, id, 1)
	padding = bytes(data_size)
	# Don’t send the packet yet, just return the final packet in this function.
	# So the function ending should look like this
	# Note: padding = bytes(data_size)
	packet = header + data + padding
	#packet = header + data
	return packet

def get_route(hostname,data_size):
	timeLeft = TIMEOUT
	for ttl in range(1,MAX_HOPS):
		for tries in range(TRIES):

			destAddr = gethostbyname(hostname)

			# SOCK_RAW is a powerful socket type. For more details:   http://sock-raw.org/papers/sock_raw
			#Fill in start
			mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)

			# Make a raw socket named mySocket
			#Fill in end

			# setsockopt method is used to set the time-to-live field.
			mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
			mySocket.settimeout(TIMEOUT)
			try:
				d = build_packet(data_size)
				mySocket.sendto(d, (hostname, 0))
				t= time.time()
				startedSelect = time.time()
				whatReady = select.select([mySocket], [], [], timeLeft)
				howLongInSelect = (time.time() - startedSelect)
				if whatReady[0] == []: # Timeout
					print("  *        *        *    Request timed out.")
					header = recvPacket[20:28]
					types, code, checksum, ID, seq = struct.unpack("bbHHh", header)
					print(types, code, checksum, ID, seq, 'ready')
				recvPacket, addr = mySocket.recvfrom(1024)
				timeReceived = time.time()
				timeLeft = timeLeft - howLongInSelect
				if timeLeft <= 0:
					print("  *        *        *    Request timed out.")
					header = recvPacket[20:28]
					types, code, checksum, ID, seq = struct.unpack("bbHHh", header)
					print(types, code, checksum, ID, seq, 'timeLeft')

			except timeout:
				header = recvPacket[20:28]
				# gets the type from the packet
				types, code, checksum, ID, seq = struct.unpack("bbHHh", header)
				print(types, code, checksum, ID, seq)
				if types == 3:
					if code == 0:
						print('Destination network unreachable')
					elif code == 1:
						print('Destination network unreachable')
					elif code == 2:
						print('Destination network unreachable')
					elif code == 3:
						print('Destination network unreachable')
					elif code == 4:
						print('Destination network unreachable')
					elif code == 5:
						print('Destination network unreachable')
					elif code == 6:
						print('Destination network unreachable')
					elif code == 7:
						print('Destination network unreachable')

				elif types == 11:
					bytes = struct.calcsize("d")
					timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
					print("  %d    rtt=%.0f ms    %s" %(ttl, (timeReceived-t)*1000, addr[0]))
				continue

			else:
				#Fill in start
				#Fetch the icmp type from the IP packet
				# adapted from: https://stackoverflow.com/questions/19897209/troubleshooting-typeerror-ord-expected-string-of-length-1-but-int-found
				header = recvPacket[20:28]
				# gets the type from the packet
				types, code, checksum, ID, seq = struct.unpack("bbHHh", header)
				print(types, code, checksum, ID, seq)
				#Fill in end
				if types == 11:
					bytes = struct.calcsize("d")
					timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
					print("  %d    rtt=%.0f ms    %s" %(ttl, (timeReceived -t)*1000, addr[0]))

				elif types == 3:
					bytes = struct.calcsize("d")
					timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
					print("  %d    rtt=%.0f ms    %s" %(ttl, (timeReceived-t)*1000, addr[0]))

				elif types == 0:
					bytes = struct.calcsize("d")
					timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
					print("  %d    rtt=%.0f ms    %s" %(ttl, (timeReceived - timeSent)*1000, addr[0]))
					return

				else:
					print("error")
				break
			finally:
				mySocket.close()


print('Argument List: {0}'.format(str(sys.argv)))

data_size = 0
if len(sys.argv) >= 2:
	data_size = int(sys.argv[1])

get_route("oregonstate.edu",data_size)
#get_route("gaia.cs.umass.edu",data_size)
