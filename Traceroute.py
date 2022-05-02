
# Adapted from companion material available for the textbook Computer Networking: A Top-Down Approach, 6th Edition
# Kurose & Ross ©2013
from __future__ import division
from statistics import mean
from socket import *
import os
import sys
import struct
import time
import select
import binascii


ICMP_ECHO_REQUEST = 8
MAX_HOPS = 40
TIMEOUT  = 2.0
TRIES    = 1

#list that contains raw data from the socket
rawData = []

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
	# adapted from: https://stackoverflow.com/questions/34614893/how-is-an-icmp-packet-constructed-in-python
	# First, make the header of the packet, then append the checksum to the header,
	# then finally append the data
	# create an initial header
	id = os.getpid()
	header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, id, 1)
	data = struct.pack('d', time.time())
	#calculate checksum
	myChecksum = checksum(header + data)
	myChecksum = htons(myChecksum)
	#append the data and checksum to the header
	header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, id, 1)
	padding = bytes(data_size)
	# Don’t send the packet yet, just return the final packet in this function.
	# So the function ending should look like this
	# Note: padding = bytes(data_size)
	packet = header + data + padding
	return packet

def get_route(hostname,data_size):
	#count to let users know that the programing is still running
	funny = 0

	timeLeft = TIMEOUT
	for ttl in range(1,MAX_HOPS):
		for tries in range(TRIES):
			destAddr = gethostbyname(hostname)

			# SOCK_RAW is a powerful socket type. For more details:   http://sock-raw.org/papers/sock_raw
			#Fill in start
			#create the socket
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
					#print("  *        *        *    Request timed out.")
					#let users know the program is running
					print('Legend, wait for it ...', funny)
					funny += 1

				recvPacket, addr = mySocket.recvfrom(1024)
				timeReceived = time.time()
				timeLeft = timeLeft - howLongInSelect
				if timeLeft <= 0:
					#print("  *        *        *    Request timed out.")
					return

			except timeout:
				if not timeout:
					#get key info from the reply socket and append it to the list
					recvPacket, addr = mySocket.recvfrom(1024)
					header = recvPacket[20:28]
					types, code, checksum, ID, seq = struct.unpack("bbHHh", header)
					#print('type = %d, code = %d, checksum = %d, ID = %d, seq = %d' % (types, code, checksum, ID, seq))
					if tries == 0:
						rawData.append([ttl, 0, addr[0], types, code])
				else:
					#No Reply
					rawData.append([rawData[len(rawData)-1][0]+1, 0, 0, 11, 0])
				continue

			else:
				#Fill in start
				#Fetch the icmp type from the IP packet
				# adapted from: https://stackoverflow.com/questions/19897209/troubleshooting-typeerror-ord-expected-string-of-length-1-but-int-found
				# get key info from the reply socket and append it to the list
				header = recvPacket[20:28]
				types, code, checksum, ID, seq = struct.unpack("bbHHh", header)
				#print('type = %d, code = %d, checksum = %d, ID = %d, seq = %d' % (types, code, checksum, ID, seq))
				#Fill in end
				if types == 11:
					bytes = struct.calcsize("d")
					timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
					#print("  %d    rtt=%.0f ms    %s" %(ttl, (timeReceived -t)*1000, addr[0]))
					# let users know the program is running
					print('Legend, wait for it ...', funny)
					funny += 1
					#append it to the list
					rawData.append([ttl, (timeReceived -t)*1000, addr[0], types, code])

				elif types == 3:
					bytes = struct.calcsize("d")
					timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
					#print("  %d    rtt=%.0f ms    %s" %(ttl, (timeReceived-t)*1000, addr[0]))
					# append it to the list
					rawData.append([ttl, (timeReceived -t)*1000, addr[0], types, code])

				elif types == 0:
					bytes = struct.calcsize("d")
					timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
					#print("  %d    rtt=%.0f ms    %s" %(ttl, (timeReceived - timeSent)*1000, addr[0]))
					# append it to the list
					rawData.append([ttl, (timeReceived -t)*1000, addr[0], types, code])
					return
				else:
					print("error")
				break
			finally:
				mySocket.close()

# Extra Credit 2: function to parse the error code
def parse_error_code(types, code):
	error_message = None
	if types == 11:
		if code == 0:
			error_message = 'TTL expired in transit'
		elif code == 1:
			error_message = 'Fragment reassembly time exceeded'
	elif types == 3:
		if code == 0:
			error_message = 'Destination network unreachable'
		elif code == 1:
			error_message = 'Destination host unreachable'
		elif code == 2:
			error_message = 'Destination protocol unreachable'
		elif code == 3:
			error_message = 'Destination port unreachable'
		elif code == 4:
			error_message = 'Fragmentation required, and DF flag set'
		elif code == 5:
			error_message = 'Source route failed'
	elif types == 0:
		error_message = 'Echo reply'
	return error_message

# Extra Credit 1: function to calculate the min, max, average rtt and packet loss % for each packet
def get_result():
	for i in range(int(len(rawData) / 3)):
		#find if there is loss packet
		rttList = [rawData[i][1], rawData[i + int(len(rawData) / 3)][1], rawData[i + int(len(rawData) / 3 * 2)][1]]
		indices = [i for i, x in enumerate(rttList) if x == 0]
		if len(indices) == 1:
			del rttList[indices[0]]
		elif len(indices) == 2:
			del rttList[indices[1]]
			del rttList[indices[0]]

		#if all packets are loss
		if sum(rttList) == 0:
		#if max([rawData[i][1], rawData[i + int(len(rawData) / 3)][1], rawData[i + int(len(rawData) / 3 * 2)][1]]) <= 0:
			print("  %d    errorCode = %s" % (rawData[i][0], parse_error_code(int(rawData[i][3]), int(rawData[i][4]))), '                                                                          packetLoss = 100.0')
		else:
			print(
				"  %d    errorCode = %s    minRtt = %.0f ms    maxRtt = %.0f ms    aveRtt = %.0f ms    %s    packetLoss = %.1f" % (
					rawData[i][0], parse_error_code(int(rawData[i][3]), int(rawData[i][4])), min(rttList), max(rttList), mean(rttList), \
					rawData[i][2], ((3 - len(rttList)) / 3 * 100)))
			'''print("  %d    errorCode = %s    minRtt = %.0f ms    maxRtt = %.0f ms    aveRtt = %.0f ms    %s    packetLoss = %.1f" % (
				rawData[i][0], parse_error_code(int(rawData[i][3]), int(rawData[i][4])), \
				min([rawData[i][1], rawData[i + int(len(rawData) / 3)][1], rawData[i + int(len(rawData) / 3 * 2)][1]]), \
				max([rawData[i][1], rawData[i + int(len(rawData) / 3)][1], rawData[i + int(len(rawData) / 3 * 2)][1]]), \
				mean([rawData[i][1], rawData[i + int(len(rawData) / 3)][1], rawData[i + int(len(rawData) / 3 * 2)][1]]),
				rawData[i][2], ((3-len(rttList))/3 * 100)))'''

print('Argument List: {0}'.format(str(sys.argv)))

data_size = 0
if len(sys.argv) >= 2:
	data_size = int(sys.argv[1])
# funny line
print('Please wait, the app is running')

# send 3 packets to each hop
# put the website address you want to get routes here!
for i in range(3):
	get_route("oregonstate.edu",data_size)

print('Dary, Legendary!')
get_result()


#get_route("oregonstate.edu",data_size)
#get_route("gaia.cs.umass.edu",data_size)

