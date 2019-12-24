import dpkt
from struct import *

#Function to convert binary to integer
def bin_to_int(s):
    x = s.replace(" ","")
    return int(x,2)

#PartC Question 1 and 2
def http_parameters_and_protocol_version():

    #Initialising list of requests
    list_of_requests = list()
    count = 0
    ts1 = 0.0
    ts2 = 0.0
    max = -99999
    packets_sent = 0
    bytes_sent = 0

    #open and read http_1080.pcap file
    f = open('http_1080.pcap')
    pcap = dpkt.pcap.Reader(f)

    #Iterate through the pcap file
    for f in pcap:

        #converting each value in the pcap file to binary and adding it to a structure
        packet = ' '.join(format(ord(x), 'b').zfill(8) for x in f[1])
        packed_packet = pack("%ds" % len(packet), packet)

        #Identifying the TCP Packet, source port, destination port, sequence number, acknowledgement number and receive window size
        tcp_packet = packed_packet[306:]
        source = tcp_packet[:17]
        destination = tcp_packet[18:35]
        sequence = tcp_packet[36:71]
        acknowledgement = tcp_packet[72:107]

        #Adding values to list if they are part of our transaction with port 1080
        if (bin_to_int(destination) == 1080) or (bin_to_int(source) == 1080):
            list_of_requests.append((f[0], bin_to_int(source), bin_to_int(destination), bin_to_int(sequence), bin_to_int(acknowledgement), tcp_packet[124]))

        #Obtaining start time
        if bin_to_int(destination) == 1080 and tcp_packet[123] == "1" and ts1 == 0.0:
            ts1 = f[0]

        #Obtaining end time
        if bin_to_int(source) == 1080 and tcp_packet[124] == "1" :
            ts2 = f[0]
            if ts2>max:
                max = ts2

        #obtaining packets sent and bytes sent
        if bin_to_int(destination) == 1080:
            packets_sent = packets_sent + 1
            bytes_sent = len(packed_packet)/8

    print "packets sent"
    print packets_sent
    print "Bytes sent"
    print bytes_sent

    #Printing transaction wise details
    for j in list_of_requests:
        ts, s, d, seq, ack,fin = j
        if s != 1080:
            print "Request Details(time stamp, Source Port, Destination Port, Sequence Number, Acknowledgment Number)"
            print j
        if fin == "1":
            count = count+1
        else:
            print "Response Details(time stamp, Source Port, Destination Port, Sequence Number, Acknowledgment Number)"
            print j

    #check to see if there are more than 6 FIN packets
    if count >6:
        print "\n\nThis is a HTTP1.0 Packet"
        print "time to load", max-ts1, "seconds"


#Part A: Question 2(a)
def http_1081():

    #Initialising counter to check no. of TCP connections established
    x =0
    ts1 = 0.0
    ts2 = 0.0
    packets_sent = 0
    bytes_sent = 0

    #Open pcap file
    f = open('http_1081.pcap')

    #Read pcap file
    pcap = dpkt.pcap.Reader(f)

    #Iterate through the pcap file
    for f in pcap:

        #converting each value in the pcap file to binary and adding it to a structure
        packet = ' '.join(format(ord(x), 'b').zfill(8) for x in f[1])
        packed_packet = pack("%ds" % len(packet), packet)

        #Identifying the TCP Packet and destination port
        tcp_packet = packed_packet[306:]
        source = tcp_packet[:17]
        destination = tcp_packet[18:35]

        #Check to see if there are 6 connections
        if bin_to_int(destination) == 1081 and tcp_packet[123] == "1" and tcp_packet[121] == "0":
            x=x+1

        #Obtaining start time
        if bin_to_int(destination) == 1081 and tcp_packet[123] == "1" and ts1 == 0.0:
            ts1 = f[0]

        #Obtaining end time
        if bin_to_int(source) == 1081 and tcp_packet[124] == "1" and ts2 == 0.0:
            ts2 = f[0]

        #Obtaining number of packets and bytes sent
        if bin_to_int(destination) == 1081:
            packets_sent = packets_sent + 1
            bytes_sent = len(packed_packet)/8

    if x == 6:
        print "This connection is a HTTP 1.1 protocol"
        print "time to load", ts2-ts1, "seconds"
        print "Packets sent", packets_sent
        print "Bytes sent", bytes_sent

n = 0
while n!=3:
    print "Choose answer you would like to see:"
    print "1. Details of http_1080.pcap"
    print "2. Details of http_1081.pcap"
    print "3. Exit"
    print "Input Number:"
    x = input()
    if x == 1:
        http_parameters_and_protocol_version()
    if x == 2:
        http_1081()
    if x == 3:
        n=3
