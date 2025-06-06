from src.network_simulator import NetworkTrafficSimulator

simulator = NetworkTrafficSimulator()
flows = simulator.generate_mixed_traffic()
df = simulator.flows_to_dataframe(flows)

print(f"Generated {len(df)} flows")
print(f"Malicious: {df['is_malicious'].sum()}")
print("Attack types:")
print(df['attack_type'].value_counts())
