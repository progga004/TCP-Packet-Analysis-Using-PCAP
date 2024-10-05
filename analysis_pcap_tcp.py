import dpkt
import socket
import os

def inet_to_str(inet):
    """Convert inet object to a string."""
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def calculate_throughput(total_bytes, start_time, end_time):
    """Calculate the throughput of a TCP flow."""
    duration = end_time - start_time
    return total_bytes / duration if duration > 0 else 0

def get_window_scaling_factor(tcp_segment):
    """Extract the window scaling factor from TCP options."""
    for opt in dpkt.tcp.parse_opts(tcp_segment.opts):
        if opt[0] == dpkt.tcp.TCP_OPT_WSCALE:
             return int.from_bytes(opt[1], byteorder='big') 
    return 1 
def estimate_cwnd_sizes(tcp_flows):
    for flow_id, flow_data in tcp_flows.items():
        print(f"\nTCP Flow: {flow_id}")

        initial_rtt = round(flow_data.get('initial_rtt', 0), 2)

        if initial_rtt is None:
            print("  - Cannot estimate cwnd sizes without RTT.")
            continue

        packets = flow_data['packets']
        packets_with_payload = [(ts, tcp) for ts, tcp in packets if len(tcp.data) > 0]

        if len(packets_with_payload) < 2:
            print("  - Not enough data packets to estimate cwnd sizes.")
            continue

        cwnd_estimates = [0]  # Initialize for the first window
        reference_ts = packets_with_payload[0][0]  # Timestamp of the first packet

        for i in range(len(packets_with_payload)):
            ts, _ = packets_with_payload[i]

            if (ts - reference_ts) < initial_rtt:
                cwnd_estimates[-1] += 1  # Increment the last window size
            else:
                if len(cwnd_estimates) == 3:  # Only keep the first 3 estimates
                    break
                cwnd_estimates.append(1)  # Start a new window and include current packet
                reference_ts = ts  # Update reference timestamp for the new window

        # Print the estimated cwnd sizes
        for i, cwnd_size in enumerate(cwnd_estimates, 1):
            print(f"  Congestion Window {i}: {cwnd_size} packets")

def extract_all_transmissions(tcp_flows):
    transmissions_info = {}

    for flow_id, flow_data in tcp_flows.items():
        packets = flow_data['packets']
        seq_counts = {}

        for packet in packets:
            _, tcp_packet = packet
            seq_num = tcp_packet.seq
            if len(tcp_packet.data) > 0:  # Has payload
                if seq_num not in seq_counts:
                    seq_counts[seq_num] = 1
                else:
                    seq_counts[seq_num] += 1

        transmissions_info[flow_id] = seq_counts
    return transmissions_info

def calculate_timeouts(transmissions_info, triple_dup_ack_info):
    timeouts_info = {}
    
    for flow_id, seq_counts in transmissions_info.items():
        triple_acks = triple_dup_ack_info.get(flow_id, {})
        timeouts_count = 0

        for seq_num, count in seq_counts.items():
            retransmissions_due_to_triple_acks = triple_acks.get(seq_num, 0)
            potential_timeouts = count - retransmissions_due_to_triple_acks
            if potential_timeouts > 1: 
                timeouts_count += (potential_timeouts - 1)  # Subtract one to ignore the initial transmission

        timeouts_info[flow_id] = timeouts_count
       

    return timeouts_info


def extract_duplicate_seq_numbers_with_payload_and_timestamps(tcp_flows):
    duplicated_seq_info_with_payload = {}

    for flow_id, flow_data in tcp_flows.items():
        packets = flow_data['packets']
        seq_info = {}

        for packet in packets:
            timestamp, tcp_packet = packet
            seq_num = tcp_packet.seq
            has_payload = len(tcp_packet.data) > 0

            if has_payload:
                if seq_num not in seq_info:
                    seq_info[seq_num] = {'count': 1, 'timestamps': [timestamp]}
                else:
                    seq_info[seq_num]['count'] += 1
                    seq_info[seq_num]['timestamps'].append(timestamp)

        duplicated_seq_info = {seq_num: info['timestamps'] for seq_num, info in seq_info.items() if info['count'] > 1}
        
        duplicated_seq_info_with_payload[flow_id] = duplicated_seq_info

    return duplicated_seq_info_with_payload


   

def detect_triple_duplicate_acks(receiver_to_sender_packets, tcp_flows):
    duplicated_seq_info_with_payload = extract_duplicate_seq_numbers_with_payload_and_timestamps(tcp_flows)
    
    triple_dup_ack_flows = {}

    for flow_id, flow_data in receiver_to_sender_packets.items():
        packets = flow_data['packets']
        triple_dup_acks = 0
        duplicated = {}

        for i in range(3, len(packets)):
            current_ack = packets[i][1].ack
            ack_timestamp = packets[i][0]

            if current_ack == packets[i-1][1].ack == packets[i-2][1].ack:
                if current_ack not in duplicated:
                    duplicated[current_ack] = {'first_ts': ack_timestamp, 'last_ts': ack_timestamp, 'count': 1}
                else:
                    duplicated[current_ack]['last_ts'] = ack_timestamp
                    duplicated[current_ack]['count'] += 1
                    
                    if duplicated[current_ack]['count'] == 3:
                        if duplicated[current_ack]['last_ts'] > duplicated[current_ack]['first_ts']:
                            expected_seq = current_ack
                            # print("Expected seqeunce",expected_seq)
                            reversed_flow_id = (flow_id[2], flow_id[3], flow_id[0], flow_id[1])
                            # print("Duplicated ones",duplicated_seq_info_with_payload)
                            if reversed_flow_id in duplicated_seq_info_with_payload:
                                seq_timestamps = duplicated_seq_info_with_payload[reversed_flow_id].get(expected_seq, [])
                                # print("Sequence timestamps",seq_timestamps)
                                # print("Last ack",duplicated[current_ack]['last_ts'])
                                # Check if at least one packet with the expected sequence number was sent after the last triple ACK
                                if any(ts < duplicated[current_ack]['last_ts'] for ts in seq_timestamps):
                                    triple_dup_acks += 1
                                    # print("Total",triple_dup_acks)

        triple_dup_ack_flows[flow_id] = triple_dup_acks

    return triple_dup_ack_flows


def analyze_tcp_flows(filename, sender_ip, receiver_ip):
    """Analyze TCP flows in a PCAP file."""
    with open(filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        tcp_flows = {}
        receiver_to_sender_packets = {}

        
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            
            ip = eth.data
            src_ip = inet_to_str(ip.src)
            dst_ip = inet_to_str(ip.dst)

            if isinstance(ip.data, dpkt.tcp.TCP) and dst_ip == sender_ip and src_ip == receiver_ip:  
                tcp=ip.data
                flow_id = (src_ip, tcp.sport, dst_ip, tcp.dport)
                
                if flow_id not in receiver_to_sender_packets:
                    receiver_to_sender_packets[flow_id] = {
                        'packets': [(ts, tcp)], 
                        
                    }
                    
                
                receiver_to_sender_packets[flow_id]['packets'].append((ts, tcp))
            
            if isinstance(ip.data, dpkt.tcp.TCP) and src_ip == sender_ip and dst_ip == receiver_ip:
                tcp = ip.data
                flow_id = (src_ip, tcp.sport, dst_ip, tcp.dport)
                tcp_segment_len = (tcp.off * 4)+len(tcp.data)

                if flow_id not in tcp_flows and tcp.flags & dpkt.tcp.TH_SYN and not tcp.flags & dpkt.tcp.TH_ACK:

                    tcp_flows[flow_id] = {
                        'start_time': ts, 
                        'packets': [(ts, tcp)], 
                        'end_time': None, 
                        'bytes': 0,
                        'highest_ack': tcp.ack,
                        'syn_time': ts,
                        'window_scale': None,
                        'initial_rtt': None,
                        'seq_numbers': [tcp.seq],  # Initialize with the first packet's sequence number
                        'seq_timestamps': [ts]
                    }
                
                if tcp.flags & dpkt.tcp.TH_SYN and  tcp_flows[flow_id]['window_scale'] is None:
                         tcp_flows[flow_id]['window_scale'] = get_window_scaling_factor(tcp)
                
                elif flow_id in tcp_flows:
                    tcp_flows[flow_id]['packets'].append((ts, tcp))
                    tcp_flows[flow_id]['seq_numbers'].append(tcp.seq)  # Append sequence number
                    tcp_flows[flow_id]['seq_timestamps'].append(ts) # Append timestamp
                    
                    if tcp.flags & dpkt.tcp.TH_ACK and  tcp_flows[flow_id]['initial_rtt'] is None:
                       tcp_flows[flow_id]['initial_rtt'] = ts -  tcp_flows[flow_id]['syn_time']

                    if tcp.ack > tcp_flows[flow_id]['highest_ack']:
                        tcp_flows[flow_id]['highest_ack'] = tcp.ack
                        tcp_flows[flow_id]['end_time'] = ts
                tcp_flows[flow_id]['bytes'] += tcp_segment_len
                
        # Analyzing each TCP flow
        for flow_id, data in tcp_flows.items():
            print(f"TCP Flow: {flow_id}")
            
            packets=data['packets']
            
            if len(packets) > 2:  
               for i in range(2, 4):  
                 packet = packets[i][1]  
                 print(f"  Transaction {i-1} SEQ: {packet.seq}, ACK: {packet.ack}")
            # Calculate throughput
            if data['end_time'] is not None:
                throughput = calculate_throughput(data['bytes'], data['start_time'], data['end_time'])
                print(f"  - Throughput: {throughput} bytes/sec")
            else:
                print("  - Throughput cannot be calculated, flow didn't finish.")
            
            if data['window_scale'] is not None:
              scaled_window_size = tcp.win << data['window_scale']
              scaled_window_size_str = str(scaled_window_size)[:100]  
              print(f"Scaled Window Size: {scaled_window_size_str}")
            else:
              print(f"Window Size (No Scaling): {tcp.win}")
        return tcp_flows,receiver_to_sender_packets
if __name__ == "__main__":
    pcap_file = "assignment2.pcap"  
    sender_ip = "130.245.145.12"  
    receiver_ip = "128.208.2.198"  
    if os.path.exists(pcap_file):
       tcp_flows,receiver_to_sender_packets= analyze_tcp_flows(pcap_file, sender_ip, receiver_ip)
       estimate_cwnd_sizes(tcp_flows)
       triple_dup_ack_info = detect_triple_duplicate_acks(receiver_to_sender_packets,tcp_flows)
       all_transmissions = extract_all_transmissions(tcp_flows)
       timeouts_info = calculate_timeouts(all_transmissions, triple_dup_ack_info)

       for flow_id, timeouts_count in timeouts_info.items():
            print(f"Flow: {flow_id}, Timeouts: {timeouts_count}")
      
       for flow_id, count in triple_dup_ack_info.items():
            print(f"Flow: {flow_id}, Triple Duplicate ACKs: {count}")
       
      
       
    else:
        print(f"File {pcap_file} not found.")
