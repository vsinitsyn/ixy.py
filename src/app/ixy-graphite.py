import argparse
import logging as log
from datetime import datetime

from ixypy import init_device, mempool
from scapy.all import *


GRAPHITE_PORT = 2003

log.basicConfig(level=log.DEBUG, format='%(levelname)-8s %(filename)s:%(lineno)s %(message)s')


def process_metric(my_ip, pkt_buffer):
    pkt = Ether(_pkt=pkt_buffer)
    log.debug('Packet received: %r', pkt)
    if not pkt.haslayer(IP):
        return

    ip = pkt[IP]
    if ip.version != 4 or ip.dst != my_ip:
        log.debug('Ignoring packet not destined to the local IP: %s', ip.dst)
        return
    if not ip.haslayer(UDP):
        log.debug('Ignoring non-UDP packet')
        return

    udp = ip[UDP]
    if udp.dport != GRAPHITE_PORT:
        log.debug('Ignoring UDP packet not destined to Graphite (port %d)', udp.dport)
        return

    for metric in bytes(udp.payload).split(b'\n')[:-1]:
        try:
            path, value, ts = metric.split(b' ')
            log.info('Metric received from %s: %s = %s @ %s', ip.src, path, value, datetime.fromtimestamp(int(ts)))
        except (ValueError, TypeError):
            log.error('Malformed metric from %s: %s', ip.src, metric)


def run_graphite(args):
    dev = init_device(args.pci_address)
    while True:
        rx_buffers = dev.rx_batch(0, 32)  # at most 32 packets from queue 0
        for buf in rx_buffers:
            process_metric(args.ip_address, buf.data_buffer[:buf.size])
            mempool.Mempool.pools[buf.mempool_id].free_buffer(buf)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('pci_address', help='NIC PCI address e.g. 0000:00:08.0', type=str)
    parser.add_argument('ip_address', help='IP address to listen', type=str)
    parser.add_argument('-d', '--debug', help='Enable debug logs', action='store_true', default=False)
    args = parser.parse_args()
    if not args.debug:
        log.getLogger().setLevel(log.INFO)
    try:
        run_graphite(args)
    except KeyboardInterrupt:
        log.info("Graphite server has been stopped")


if __name__ == '__main__':
    main()
