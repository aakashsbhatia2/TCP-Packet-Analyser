from struct import *
import dpkt


#function to convert binary values to integer values
def bin_to_int(s):
    x = s.replace(" ","")
    return int(x,2)

#Part A: Question 1
def flows_initiated():

    #open assignment2.pcap file
    f = open('assignment2.pcap')
    count = 0

    #Read assignment2.pcap file
    pcap = dpkt.pcap.Reader(f)

    #Iterate through the pcap file
    for f in pcap:

        #converting each value in the pcap file to binary and adding it to a structure
        packet = ' '.join(format(ord(x), 'b').zfill(8) for x in f[1])
        packed_packet = pack("%ds" % len(packet), packet)

        #Identifying the TCP Packet
        tcp_packet = packed_packet[306:]

        #Checking how many SYN packets were sent and counting them
        if tcp_packet[123] == "1" and tcp_packet[120] == "0":
            count = count + 1

    #Printing output
    print "Number of TCP flows:"
    print count


#Part A: Question 2(a)
def parameters():

    #Initialising list for packets sent and set for identifying the unique source ports from requester
    list_of_requests = list()
    source_ports = set()

    #Open assignment2.pcap file
    f = open('assignment2.pcap')

    #Read assignment2.pcap file
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
        receive_window_size = tcp_packet[126:143]

        #Checking SYN packets sent to identify unique senders
        if tcp_packet[123] == "1" and tcp_packet[120] == "0":
            source_ports.add(bin_to_int(source))

        #Storing packet information in a list
        list_of_requests.append((f[0], bin_to_int(source), bin_to_int(destination), bin_to_int(sequence), bin_to_int(acknowledgement), bin_to_int(receive_window_size)*16384))

    #Iterating through the list of packets to obtain flow-wise data. Flag is used to print information for next two packets after SYN, SYN ACK, ACK
    for i in source_ports:
        flag = 0
        if flag < 2:
            for j in list_of_requests:
                if flag < 2:
                    ts, s, d, seq, ack, w = j
                    for k in list_of_requests:
                        if flag < 2:
                            ts2, s2, d2, seq2, ack2, w = k

                            #Condition to check if packet was acknowledged successfully
                            if s == i and s == d2 and d == s2 and ack2 - seq == + 1448:
                                print "Sender Packet Details(time stamp, Source Port, Destination Port, Sequence Number, Acknowledgment Number, Receive Window Size)"
                                print j
                                print "Receiver Packet Details(time stamp, Source Port, Destination Port, Sequence Number, Acknowledgment Number, Receive Window Size)"
                                print k
                                flag = flag + 1

#Part A: Question 2(c)
def compute_average_RTT():

    #Initialising list for packets sent, set for identifying the unique source ports from requester, counter for acknowledged packets and sum of RTT's
    list_of_requests = list()
    source_ports = set()
    acknowledge_packets = 0.0
    sum = 0

    #Open and read assignment2.pcap file
    f = open('assignment2.pcap')
    pcap = dpkt.pcap.Reader(f)

    # Iterate through the pcap file
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
        receive_window_size = tcp_packet[126:143]

        #Checking SYN packets sent to identify unique senders
        if tcp_packet[123] == "1" and tcp_packet[120] == "0":
            source_ports.add(bin_to_int(source))

        #Storing packet information in a list
        list_of_requests.append((f[0], bin_to_int(source), bin_to_int(destination), bin_to_int(sequence), bin_to_int(acknowledgement), bin_to_int(receive_window_size)*16384))

    #Iterating through the list of packets to obtain flow-wise data.
    for i in source_ports:
        for j in list_of_requests:
            ts, s, d, seq, ack, w = j
            for k in list_of_requests:
                ts2, s2, d2, seq2, ack2, w = k
                if s == i and s == d2 and d == s2 and (ack2 - seq == + 1448 or ack2 - seq == +1 or ack2 - seq == +24):

                    #Computing sum of RTT's
                    sum = sum + (ts2-ts)

                    #Computing sum of acknowledged packets
                    acknowledge_packets = acknowledge_packets + 1

    #Computing average RTT
    print sum/float(acknowledge_packets)


#Part A: Question 2(b)
def compute_throughput():

    #Initialising set of sourceports to capture unique sourceports, dictionary to store start and end time of transactions and total length of packets in bits
    set_of_sourceports = set()
    set_of_start_time = dict()
    set_end_time = dict()
    total_length_of_packets = dict()

    #Open and read pcap file
    f = open('assignment2.pcap')
    pcap = dpkt.pcap.Reader(f)

    #Iterate through pcap file
    for f in pcap:

        #converting each value in the pcap file to binary and adding it to a structure
        packet = ' '.join(format(ord(x), 'b').zfill(8) for x in f[1])
        packed_packet = pack("%ds" % len(packet), packet)

        #Identifying the TCP Packet, source port, destination port
        tcp_packet = packed_packet[306:]
        source = tcp_packet[:17]
        destination = tcp_packet[18:35]

        #Checking SYN packets sent to identify unique senders and storing start time of SYN packets to compute throughput
        if tcp_packet[123] == "1" and tcp_packet[120] == "0":
            set_of_sourceports.add(bin_to_int(source))
            set_of_start_time.update({bin_to_int(source): f[0]})

        # Checking FIN packets sent to identify end time to compute throughput
        if tcp_packet[124] == "1":
            set_end_time.update({bin_to_int(destination): f[0]})

    #Iterating through the pcap files to obtain flow-wise throughput
    for i in set_of_sourceports:
        total_length = 0
        f = open('assignment2.pcap')
        pcap = dpkt.pcap.Reader(f)
        for f in pcap:
            packet = ' '.join(format(ord(x), 'b').zfill(8) for x in f[1])
            packed_packet = pack("%ds" % len(packet), packet)
            tcp_packet = packed_packet[306:]
            source = tcp_packet[:17]

            #Checking is sender is not port 80 and adding packet length to obtain total bits sent
            if bin_to_int(source) == i:
                total_length = total_length + len(packed_packet)

                #Storing total bits sent in a dictionary with key as source port number
                total_length_of_packets.update({i: total_length})

    #Computing diff in time and throughput for each flow
    time_difference = {key: set_end_time[key] - set_of_start_time.get(key, 0) for key in set_end_time.keys()}
    throughput = {key: round(total_length_of_packets[key]/ time_difference.get(key, 0)) for key in total_length_of_packets.keys()}
    print "Flow-wise Throughput(in bits/second): \n"
    print throughput

#Part A: Question 2(d)
def compute_lossrate():

    #Initialising list for packets sent, set for identifying the unique source ports from requester, counter for packets sent, received and acknowledged
    list_of_requests = list()
    source_ports = set()

    #Open and read pcap file
    f = open('assignment2.pcap')
    pcap = dpkt.pcap.Reader(f)

    # Iterate through the pcap file
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
        receive_window_size = tcp_packet[126:143]

        #Checking SYN packets sent to identify unique senders
        if tcp_packet[123] == "1" and tcp_packet[120] == "0":
            source_ports.add(bin_to_int(source))

        #Storing packet information in a list
        list_of_requests.append((f[0], bin_to_int(source), bin_to_int(destination), bin_to_int(sequence), bin_to_int(acknowledgement), bin_to_int(receive_window_size)*16384))

    #Iterating through packets to obtain flow-wise loss-rate
    for i in source_ports:
        packets_sent = 0
        packets_acknowledged = 0
        for j in list_of_requests:
            ts, s, d, seq, ack, w = j

            #incrementing packets sent if source port == i
            if s == i:
                packets_sent = packets_sent + 1
            for k in list_of_requests:
                ts2, s2, d2, seq2, ack2, w = k

                #Checking if packet is acknowledged and incrementing acknowledged counter
                if s == i and s == d2 and d == s2 and (ack2 - seq == + 1448 or ack2 - seq == +24 or ack2 - seq == +1):
                    packets_acknowledged = packets_acknowledged + 1

        #Computing loss rate and printing it
        loss_rate = packets_sent - packets_acknowledged
        loss_rate2 = (loss_rate/float(packets_sent))* 100
        print "packet loss for sourceport", i, "is", loss_rate2, "%"

#Part B: Question 2
def retransmissions_timeout():

    #Initialising list for packets sent, set for identifying the unique requests
    list_of_requests = list()
    set_of_requests = set()

    #Open and read pcap file
    f = open('assignment2.pcap')
    pcap = dpkt.pcap.Reader(f)

    # Iterate through the pcap file
    for f in pcap:

        #converting each value in the pcap file to binary and adding it to a structure
        packet = ' '.join(format(ord(x), 'b').zfill(8) for x in f[1])
        packed_packet = pack("%ds" % len(packet), packet)

        #Identifying the TCP Packet and source port
        tcp_packet = packed_packet[306:]
        source = tcp_packet[:17]

        #If source is from receiver i.e. 80, append list of requests with packet and set of requests with packet
        if bin_to_int(source) == 80:
            list_of_requests.append(tcp_packet)
            set_of_requests.add(tcp_packet)

    #Obtaining number of retransmissions
    print "Number of retransmissions due to time-out is:", len(list_of_requests) - len(set_of_requests)

#Part B: Question 2
def retransmissions_triple_duplicate_ack():

    # Initialising list for packets sent, set for identifying the unique requests
    list_of_requests = list()
    set_of_requests = set()

    # Open and read pcap file
    f = open('assignment2.pcap')
    pcap = dpkt.pcap.Reader(f)

    # Iterate through the pcap file
    for f in pcap:

        # converting each value in the pcap file to binary and adding it to a structure
        packet = ' '.join(format(ord(x), 'b').zfill(8) for x in f[1])
        packed_packet = pack("%ds" % len(packet), packet)

        # Identifying the TCP Packet and source port
        tcp_packet = packed_packet[306:]
        source = tcp_packet[:17]

        # If source is from sender i.e. not equal to 80, append list of requests with packet and set of requests with packet
        if bin_to_int(source) != 80:
            list_of_requests.append(tcp_packet)
            set_of_requests.add(tcp_packet)

    # Obtaining number of retransmissions
    print "Number of retransmissions due to time-out is:", len(list_of_requests) - len(set_of_requests)

#Part B: Question 1
def cwnd():

    # Initialising list for packets sent, set for identifying the unique requests and cwnd(answer)
    list_of_requests = list()
    source_ports = set()
    answer = set()

    # Open and read pcap file
    f = open('assignment2.pcap')
    pcap = dpkt.pcap.Reader(f)

    # Iterate through the pcap file
    for f in pcap:

        # converting each value in the pcap file to binary and adding it to a structure
        packet = ' '.join(format(ord(x), 'b').zfill(8) for x in f[1])
        packed_packet = pack("%ds" % len(packet), packet)

        # Identifying the TCP Packet, source port and destination port
        tcp_packet = packed_packet[306:]
        source = tcp_packet[:17]
        destination = tcp_packet[18:35]

        #Checking SYN packets sent to identify unique senders
        if tcp_packet[123] == "1" and tcp_packet[120] == "0":
            source_ports.add(bin_to_int(source))

        #Adding packets to list of requests
        list_of_requests.append((bin_to_int(source), bin_to_int(destination), tcp_packet[123], tcp_packet[120]))

    #Identifying the flow-wise cwnd
    for i in source_ports:

        #initialising flag to print first 10 cwnds
        flag2 = 0
        packets_sent = 0
        answer.clear()
        print i
        for j in list_of_requests:
            s, d, syn, ack = j
            if s == i and syn == "0":
                packets_sent = packets_sent + 1
            if s == 80 and d == i and syn == "0" and packets_sent != 0:
                answer.add(packets_sent)

        #Printing cwnd
        for x in sorted(answer):
            if flag2 < 10:
                print x
                flag2 = flag2+1

n = 0
while n!=9:
    print "Choose answer you would like to see:"
    print "1. Number of TCP Flows initiated"
    print "2. Parameters for first 2 transactions after connection is established"
    print "3. Throughput"
    print "4. Loss rate"
    print "5. Average RTT"
    print "6. Retransmissions due to timeout"
    print "7. Retransmissions due to triple duplicate ack"
    print "8. First 10 Congestion windows"
    print "9. Exit"
    print "Input Number:"

    x = input()
    if x == 1:
        flows_initiated()
    if x == 2:
        parameters()
    if x == 3:
        compute_throughput()
    if x == 4:
        compute_lossrate()
    if x == 5:
        compute_average_RTT()
    if x == 6:
        retransmissions_timeout()
    if x == 7:
        retransmissions_triple_duplicate_ack()
    if x == 8:
        cwnd()
    if x == 9:
        n=9