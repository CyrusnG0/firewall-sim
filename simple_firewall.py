import random
import ipaddress
from datetime import datetime, timedelta

# Define firewall rule class for extensibility
class FirewallRule:
    def __init__(self, action, ip=None, network=None, protocol=None, port=None, priority=100, expire_time=None):
        """
        action: 'block', 'allow', 'alert', 'rate-limit' etc.
        ip: exact IP address string
        network: CIDR string for subnet
        protocol: 'tcp', 'udp', 'icmp', or None for any
        port: integer or None for any
        priority: lower number means higher priority
        expire_time: datetime object when rule expires, None means permanent
        """
        self.action = action
        self.ip = ip
        self.network = ipaddress.ip_network(network) if network else None
        self.protocol = protocol
        self.port = port
        self.priority = priority
        self.expire_time = expire_time

    def matches(self, ip, protocol=None, port=None):
        ip_obj = ipaddress.ip_address(ip)

        # Check expiration
        if self.expire_time and datetime.now() > self.expire_time:
            return False

        # Check IP match
        if self.ip and ip != self.ip:
            return False
        if self.network and ip_obj not in self.network:
            return False

        # Check protocol match
        if self.protocol and protocol != self.protocol:
            return False

        # Check port match
        if self.port and port != self.port:
            return False

        return True

# Firewall class to hold and evaluate rules
class Firewall:
    def __init__(self, default_action="allow"):
        self.rules = []
        self.default_action = default_action
        self.log = []

    def add_rule(self, rule):
        self.rules.append(rule)
        # Keep rules sorted by priority
        self.rules.sort(key=lambda r: r.priority)

    def check_packet(self, ip, protocol=None, port=None):
        for rule in self.rules:
            if rule.matches(ip, protocol, port):
                self.log_action(ip, protocol, port, rule.action, rule)
                return rule.action
        # No matching rule, apply default
        self.log_action(ip, protocol, port, self.default_action, None)
        return self.default_action

    def log_action(self, ip, protocol, port, action, rule):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rule_desc = f"Rule(priority={rule.priority}, action={rule.action})" if rule else "Default policy"
        log_entry = f"{timestamp} - IP: {ip}, Protocol: {protocol or 'any'}, Port: {port or 'any'}, Action: {action}, Matched: {rule_desc}"
        self.log.append(log_entry)
        print(log_entry)

    def show_log(self):
        print("\nFirewall log:")
        for entry in self.log:
            print(entry)

# Simulate traffic with random IPs, protocols, and ports
def simulate_traffic(firewall, num_packets=20):
    protocols = ['tcp', 'udp', 'icmp']
    for _ in range(num_packets):
        ip = f"192.168.1.{random.randint(1, 30)}"
        protocol = random.choice(protocols)
        port = random.choice([22, 80, 443, 8080, None]) 
        action = firewall.check_packet(ip, protocol, port)
        print(f"Packet: IP={ip}, Protocol={protocol}, Port={port}, Action={action}")

def main():
    firewall = Firewall(default_action="allow")

    # Add some rules
    firewall.add_rule(FirewallRule(action="block", ip="192.168.1.5", priority=1))
    firewall.add_rule(FirewallRule(action="block", network="192.168.1.0/28", priority=5))  # block 192.168.1.0 - 15
    firewall.add_rule(FirewallRule(action="block", protocol="icmp", priority=10))  # block all ICMP
    firewall.add_rule(FirewallRule(action="allow", protocol="tcp", port=80, priority=20))  # allow HTTP
    firewall.add_rule(FirewallRule(action="block", port=22, priority=15))  # block SSH on any IP

    simulate_traffic(firewall, num_packets=25)

    firewall.show_log()

if __name__ == "__main__":
    main()