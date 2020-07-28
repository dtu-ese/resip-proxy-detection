from scapy.all import *
import itertools
import operator

network_flow = []
packet_position = 0

def read_pcap(pkt):
    global packet_position
    if 'IP' in pkt:
        if 'DNS' in pkt:
            flow = {
                "src_ip": (pkt['IP'].src),
                "dst_ip": (pkt['IP'].dst),
                "time": (pkt.time),
                "size_of_packet": len(pkt),
                "packet_position": packet_position,
                "isDNS": 1
            }
        else:
            flow = {
                "src_ip": (pkt['IP'].src),
                "dst_ip": (pkt['IP'].dst),
                "time": (pkt.time),
                "size_of_packet": len(pkt),
                "packet_position": packet_position,
                "isDNS": 0
            }
        network_flow.append(flow)
        packet_position += 1
    else :
        pass




filename = "30mins_delay_509normal_70sus.pcapng"  ## input file goes here
myreader = sniff(offline=filename, prn=read_pcap, store=0)

print("read the file with name:", filename)
print("number of packets read from pcap file:", len(network_flow))

ip_adresses = ['172.28.128.4', '10.0.2.15'] ## ip address of the compromised device

outgoing_flow = []
incoming_flow = []

def find_distance(position, ipaddress):

    temp_list = network_flow[::-1]
    distance = 0
    start_point = len(temp_list) - position
    end_point = len(temp_list)

    for item in itertools.islice(temp_list, start_point, end_point):
        if item['src_ip'] == ipaddress or item['dst_ip'] == ipaddress:
            distance = position - item['packet_position'] - 1
            break

    return distance

def max_data_received(position, numofpackets):

    incoming_data = dict()
    start_point = position - numofpackets
    end_point = start_point + numofpackets

    for item in itertools.islice(network_flow, start_point, end_point):

        if item['dst_ip'] in ip_adresses:
            if item['src_ip'] in incoming_data.keys():
                incoming_data[item['src_ip']] += item['size_of_packet']
            else:
                incoming_data.update({item['src_ip'] : item['size_of_packet']})

    if bool(incoming_data):
        ip_of_maxdata = max(incoming_data.items(), key=operator.itemgetter(1))[0]
        return incoming_data[ip_of_maxdata]
    else:
        return 0

def total_data_sent(position, ipaddress):

    if position == 11455:
        pass

    total_data = 0
    start_point = position
    end_point = len(network_flow)

    start_time = network_flow[start_point]['time']
    time_threshold = 0.01               ## time threshold for the Data Check

    for item in itertools.islice(network_flow, start_point, end_point):

        time_diff = item['time'] - start_time

        if time_diff < time_threshold:
            if item['dst_ip'] == ipaddress:
                total_data += item['size_of_packet']
        else:
            break

    return total_data

def dns_check(position, numofpackets):

    iterator = position - numofpackets
    end_of_flow = iterator + numofpackets;

    start_time = network_flow[iterator-1]['time']
    time_difference = 100                               ### Defined as 100 sec, might be int max does not matter

    while(True):

        packet = network_flow[iterator]
        if iterator == end_of_flow:
            break

        if packet['isDNS'] == 1:
            end_time = packet['time']
            time_difference = end_time - start_time
            break

        iterator += 1

    return time_difference

previous_incoming_flow = None
previous_outgoing_flow = None
suspicious_ip_list = []

for element in network_flow:
    ## check if it is an incoming flow

    if element['dst_ip'] in ip_adresses:

        ## chck if curr. conn is same with the last one

        if element['src_ip'] == previous_incoming_flow:
            pass

        ## if a src. of conn. never occured before

        elif element['src_ip'] not in incoming_flow:
            incoming_flow.append(element['src_ip'])

        previous_incoming_flow = element['src_ip']

    ## check if it is an outgoing flow

    elif element['src_ip'] in ip_adresses:

        num_packets_between = find_distance(element['packet_position'], element['dst_ip'])

        if element['dst_ip'] == previous_outgoing_flow:
            pass

        elif element['dst_ip'] not in outgoing_flow:
            outgoing_flow.append(element['dst_ip'])

        elif element['dst_ip'] in incoming_flow and num_packets_between > 10 and num_packets_between < 250:
            suspicious_activity = {
                "IP": element['dst_ip'],
                "pos": element['packet_position'],
                "num_pack": num_packets_between,
                "violations": "F"
            }
            suspicious_ip_list.append( suspicious_activity )

        previous_outgoing_flow = element['dst_ip']

## suspicious_ip_list : item[0] ipaddress, item[1] position of occurence, item[2] number of packets flow between suspicion, item[3] violations

for item in suspicious_ip_list[:]:

    max_data_outgoing = total_data_sent(item["pos"], item["IP"])
    max_data_incoming = max_data_received(item["pos"], item["num_pack"])

    if max_data_incoming <= max_data_outgoing:# or ratio > 0.5:
        item["violations"] += "D"

## DNS Check on suspicious list

for item in suspicious_ip_list[:]:
    time_diff = dns_check(item["pos"], item["num_pack"])

    if time_diff >= 0.15:             ## time threshold for the DNS check
        continue
    else:
        item["violations"] += "S"


f = open("suspicious_connections.txt", "a")
for item in suspicious_ip_list:
    f.write('IP address: '+ str(item['IP'])
            + ', position:' + str(item['pos'])
            + ', violations:' + item['violations']
            + ', num_pack:' + str(item['num_pack'])
                         + '\n')
f.close()
