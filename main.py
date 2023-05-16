from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo
from mininet.cli import CLI
from scapy.all import *
import threading
import time
import network_topology as topo
import sdc_controller as ctrl


class MyTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        h1 = self.addHost('h1', ip='10.0.1.1/24')
        h2 = self.addHost('h2', ip='10.0.1.2/24')
        h3 = self.addHost('h3', ip='10.0.1.3/24')
        h4 = self.addHost('h4', ip='10.0.1.4/24')
        h5 = self.addHost('h5', ip='10.0.2.1/24')
        h6 = self.addHost('h6', ip='10.0.2.2/24')
        h7 = self.addHost('h7', ip='10.0.2.3/24')
        h8 = self.addHost('h8', ip='10.0.2.4/24')
        h9 = self.addHost('h9', ip='10.0.3.1/24')
        h10 = self.addHost('h10', ip='10.0.3.2/24')
        h11 = self.addHost('h11', ip='10.0.3.3/24')
        h12 = self.addHost('h12', ip='10.0.3.4/24')
        h13 = self.addHost('h13', ip='10.0.4.1/24')
        h14 = self.addHost('h14', ip='10.0.4.2/24')
        h15 = self.addHost('h15', ip='10.0.4.3/24')
        h16 = self.addHost('h16', ip='10.0.4.4/24')

        self.addLink(s1, h1)
        self.addLink(s1, h2)
        self.addLink(s1, h3)
        self.addLink(s1, h4)
        self.addLink(s2, h5)
        self.addLink(s2, h6)
        self.addLink(s2, h7)
        self.addLink(s2, h8)
        self.addLink(s3, h9)
        self.addLink(s3, h10)
        self.addLink(s3, h11)
        self.addLink(s3, h12)
        self.addLink(s4, h13)
        self.addLink(s4, h14)
        self.addLink(s4, h15)
        self.addLink(s4, h16)
        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s2, s4)
        self.addLink(s3, s4)

if __name__ == '__main__':
    topo = MyTopo()
    net = Mininet(topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1'))
    net.start()
    for switch in net.switches:
        switch.cmd('ovs-vsctl set Bridge %s protocols=OpenFlow13' % switch.name)
    net.pingAll()
    net.stop()

ARP_REQUEST = 1
ARP_REPLY = 2
ICMP_REQUEST = 8
ICMP_REPLY = 0
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

def listen_network():
    while True:
        time.sleep(1)
        pkt = sniff(filter='tcp or udp or arp or icmp', count=1)
        if ARP in pkt[0]:
            handle_arp(pkt[0])
        elif ICMP in pkt[0]:
            handle_icmp(pkt[0])
        elif TCP in pkt[0]:
            handle_tcp(pkt[0])
        elif UDP in pkt[0]:
            handle_udp(pkt[0])

def handle_arp(pkt):
    src_ip = pkt.getlayer(ARP).psrc
    dst_ip = pkt.getlayer(ARP).pdst
    src_mac = pkt.getlayer(ARP).hwsrc
    dst_mac = pkt.getlayer(ARP).hwdst
    if pkt.getlayer(ARP).op == ARP_REQUEST:
        print(f'Received ARP request from {src_ip} ({src_mac}) for {dst_ip}')
        route = topo.find_path(src_ip, dst_ip)
        print(f'Found path: {route}')
        for i, switch in enumerate(route[:-1]):
            match = f'{src_ip}/32'
            actions = f'{route[i+1]}-eth1'
            ctrl.add_flow_rule(switch, match, actions)
        print('Added flow rules for ARP request')
    elif pkt.getlayer(ARP).op == ARP_REPLY:
        print(f'Received ARP reply from {src_ip} ({src_mac}) to {dst_ip} ({dst_mac})')

def handle_icmp(pkt):
    src_ip = pkt.getlayer(IP).src
    dst_ip = pkt.getlayer(IP).dst
    if pkt.getlayer(ICMP).type == ICMP_REQUEST:
        print(f'Received ICMP request from {src_ip} to {dst_ip}')
        route = topo.find_path(src_ip, dst_ip)
        print(f'Found path: {route}')
        for i, switch in enumerate(route[:-1]):
            match = f'src={src_ip},dst={dst_ip},proto=icmp'
            actions = f'{route[i+1]}-eth1'
            ctrl.add_flow_rule(switch, match, actions)
        print('Added flow rules for ICMP request')
    elif pkt.getlayer(ICMP).type == ICMP_REPLY:
        print(f'Received ICMP reply from {src_ip} to {dst_ip}')

def handle_tcp(pkt):
    src_ip = pkt.getlayer(IP).src
    dst_ip = pkt.getlayer(IP).dst
    src_port = pkt.getlayer(TCP).sport
    dst_port = pkt.getlayer(TCP).dport
    flags = pkt.getlayer(TCP).flags
    if flags & 0x02:
        print(f'Received TCP SYN from {src_ip}:{src_port} to {dst_ip}:{dst_port}')
        route = topo.find_path(src_ip, dst_ip)
        print(f'Found path: {route}')
        for i, switch in enumerate(route[:-1]):
            match = f'src={src_ip},dst={dst_ip},proto=tcp,tcp_dst={dst_port}'
            actions = f'{route[i+1]}-eth1'
            ctrl.add_flow_rule(switch, match, actions)
        print('Added flow rules for TCP SYN')
    elif flags & 0x10:
        print(f'Received TCP ACK from {src_ip}:{src_port} to {dst_ip}:{dst_port}')
        route = topo.find_path(src_ip, dst_ip)
        print(f'Found path: {route}')
        for i, switch in enumerate(route[:-1]):
            match = f'src={dst_ip},dst={src_ip},proto=tcp,tcp_src={dst_port}'
            actions = f'{route[i+1]}-eth1'
            ctrl.add_flow_rule(switch, match, actions)
        print('Added flow rules for TCP ACK')

def handle_udp(pkt):
    src_ip = pkt.getlayer(IP).src
    dst_ip = pkt.getlayer(IP).dst
    src_port = pkt.getlayer(UDP).sport
    dst_port = pkt.getlayer(UDP).dport
    print(f'Received UDP packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}')
    route = topo.find_path(src_ip, dst_ip)
    print(f'Found path: {route}')
    for i, switch in enumerate(route[:-1]):
        match = f'src={src_ip},dst={dst_ip},proto=udp,udp_dst={dst_port}'
        actions = f'{route[i+1]}-eth1'
        ctrl.add_flow_rule(switch, match, actions)
    print('Added flow rules for UDP packet')

if __name__ == '__main__':
    # Start network topology
    topo = Topo()
    net = Mininet(topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1'))
    net.start()
    for switch in net.switches:
        switch.cmd('ovs-vsctl set Bridge %s protocols=OpenFlow13' % switch.name)

    # Listen to network traffic
    listener = threading.Thread(target=listen_network)
    listener.daemon = True
    listener.start()

    # Wait for user input to quit program
    while True:
        cmd = input('Type q to quit\n')
        if cmd == 'q':
            break

    # Stop network topology and exit
    CLI(net)
    net.stop()

