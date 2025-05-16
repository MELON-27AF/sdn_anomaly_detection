from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time

class AnomalyDetectionTopo(Topo):
    """Topology for SDN anomaly detection testing"""

    def build(self):
        # Add switches
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')

        # Add hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

        # Connect hosts to switches
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s2)

        # Connect switches
        self.addLink(s1, s2)


def run():
    """Create network and run CLI"""
    topo = AnomalyDetectionTopo()

    # Create network with remote controller
    net = Mininet(
        topo=topo,
        controller=RemoteController('c0', ip='127.0.0.1', port=6653),
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=True
    )

    # Start network
    net.start()
    info('*** Network started\n')

    # Give controller time to connect to switches
    time.sleep(3)

    # Run CLI
    CLI(net)

    # Stop network
    net.stop()
    info('*** Network stopped\n')


if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    run()
