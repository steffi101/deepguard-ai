import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import random
import json
import ipaddress
from dataclasses import dataclass
from typing import List, Dict, Tuple
import uuid
import hashlib
import time

@dataclass
class NetworkFlow:
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    duration: float
    flags: List[str]
    is_malicious: bool
    attack_type: str = None
    
class NetworkTrafficSimulator:
    def __init__(self):
        self.internal_networks = [
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12')
        ]
        self.external_networks = [
            ipaddress.IPv4Network('8.8.8.0/24'),
            ipaddress.IPv4Network('1.1.1.0/24'),
            ipaddress.IPv4Network('104.16.0.0/16')
        ]
        

        self.service_ports = {
            80: {'protocol': 'HTTP', 'typical_bytes': (500, 50000)},
            443: {'protocol': 'HTTPS', 'typical_bytes': (800, 100000)},
            22: {'protocol': 'SSH', 'typical_bytes': (100, 2000)},
            53: {'protocol': 'DNS', 'typical_bytes': (50, 500)},
            25: {'protocol': 'SMTP', 'typical_bytes': (200, 10000)},
            21: {'protocol': 'FTP', 'typical_bytes': (100, 1000000)},
            3389: {'protocol': 'RDP', 'typical_bytes': (1000, 50000)},
            1433: {'protocol': 'SQL', 'typical_bytes': (200, 100000)}
        }
        

        self.attack_patterns = {
            'port_scan': {
                'description': 'Systematic scanning of multiple ports',
                'indicators': {
                    'port_variety': 'high',
                    'connection_duration': 'very_short',
                    'bytes_transferred': 'minimal',
                    'frequency': 'rapid'
                }
            },
            'ddos': {
                'description': 'Distributed Denial of Service',
                'indicators': {
                    'packet_rate': 'extremely_high',
                    'source_variety': 'high',
                    'target_focus': 'single',
                    'bytes_per_packet': 'small'
                }
            },
            'brute_force': {
                'description': 'Password brute force attempt',
                'indicators': {
                    'failed_attempts': 'high',
                    'target_port': 'authentication',
                    'timing_pattern': 'regular',
                    'source_persistence': 'high'
                }
            },
            'data_exfiltration': {
                'description': 'Large data transfer to external location',
                'indicators': {
                    'bytes_outbound': 'extremely_high',
                    'duration': 'extended',
                    'unusual_hours': 'likely',
                    'compression_signs': 'possible'
                }
            },
            'lateral_movement': {
                'description': 'Internal network reconnaissance',
                'indicators': {
                    'internal_scanning': 'high',
                    'privilege_escalation': 'attempted',
                    'multiple_targets': 'yes',
                    'stealth_timing': 'variable'
                }
            }
        }
    
    def generate_internal_ip(self) -> str:
        """Generate a realistic internal IP address"""
        network = random.choice(self.internal_networks)

        host_id = random.randint(1, min(1000, network.num_addresses - 2))
        return str(network.network_address + host_id)
    
    def generate_external_ip(self) -> str:
        """Generate a realistic external IP address"""
        network = random.choice(self.external_networks)
        host_id = random.randint(1, min(254, network.num_addresses - 2))
        return str(network.network_address + host_id)
    
    def generate_normal_traffic(self, count: int = 1000) -> List[NetworkFlow]:
        """Generate normal, benign network traffic"""
        flows = []
        base_time = datetime.now() - timedelta(hours=1)
        
        for i in range(count):

            timestamp = base_time + timedelta(seconds=random.randint(0, 3600))
            

            source_ip = self.generate_internal_ip()
            dest_ip = self.generate_external_ip()
            

            dest_port = np.random.choice(
                list(self.service_ports.keys()),
                p=[0.4, 0.35, 0.05, 0.1, 0.03, 0.02, 0.03, 0.02]  
            )
            
            source_port = random.randint(32768, 65535)  
            
            service_info = self.service_ports[dest_port]
            min_bytes, max_bytes = service_info['typical_bytes']
            

            bytes_sent = int(np.random.lognormal(np.log(min_bytes), 1))
            bytes_received = int(np.random.lognormal(np.log(max_bytes), 1.5))
            

            packets_sent = max(1, bytes_sent // 1500)
            packets_received = max(1, bytes_received // 1500)
            

            if dest_port in [80, 443]:  
                duration = np.random.exponential(5.0)  
            elif dest_port == 22:  # SSH
                duration = np.random.exponential(300.0)  
            else:
                duration = np.random.exponential(30.0)
            
            flows.append(NetworkFlow(
                timestamp=timestamp,
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                protocol='TCP',
                bytes_sent=bytes_sent,
                bytes_received=bytes_received,
                packets_sent=packets_sent,
                packets_received=packets_received,
                duration=duration,
                flags=['SYN', 'ACK', 'FIN'],
                is_malicious=False
            ))
        
        return flows
    
    def generate_mixed_traffic(self, normal_ratio: float = 0.85) -> List[NetworkFlow]:
        """Generate realistic mix of normal and malicious traffic"""
        total_flows = random.randint(1000, 2000)
        normal_count = int(total_flows * normal_ratio)
        
        flows = []
        

        flows.extend(self.generate_normal_traffic(normal_count))
        

        remaining = total_flows - normal_count
        for i in range(remaining):
            flow = self.generate_normal_traffic(1)[0]
            flow.is_malicious = True
            flow.attack_type = random.choice(['ddos', 'brute_force', 'port_scan', 'data_exfiltration'])
            flows.append(flow)
        

        flows.sort(key=lambda x: x.timestamp)
        
        return flows
    
    def flows_to_dataframe(self, flows: List[NetworkFlow]) -> pd.DataFrame:
        """Convert flows to pandas DataFrame for ML processing"""
        data = []
        for flow in flows:
            data.append({
                'timestamp': flow.timestamp,
                'source_ip': flow.source_ip,
                'dest_ip': flow.dest_ip,
                'source_port': flow.source_port,
                'dest_port': flow.dest_port,
                'protocol': flow.protocol,
                'bytes_sent': flow.bytes_sent,
                'bytes_received': flow.bytes_received,
                'packets_sent': flow.packets_sent,
                'packets_received': flow.packets_received,
                'duration': flow.duration,
                'flags': ','.join(flow.flags),
                'is_malicious': flow.is_malicious,
                'attack_type': flow.attack_type or 'normal'
            })
        
        return pd.DataFrame(data)


if __name__ == "__main__":
    simulator = NetworkTrafficSimulator()
    

    flows = simulator.generate_mixed_traffic()
    df = simulator.flows_to_dataframe(flows)
    
    print(f"Generated {len(df)} network flows")
    print(f"Malicious flows: {df['is_malicious'].sum()}")
    print(f"Attack types: {df['attack_type'].value_counts()}")
    

    print("\nSample flows:")
    print(df.head(10))
