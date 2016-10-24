from datetime import datetime
from scapy.all import *
from collections import Counter
import sys
from threading import Thread
from collections import defaultdict
import datetime
from time import sleep

iface="wlan0"

macs = defaultdict()


def run_sniffer():
    sniff(iface=iface, prn=handle_packet)


def handle_packet(packet):
    if packet.haslayer(Dot11):
        if packet[Dot11].addr2 is not None:
            #print Counter(tupleslist).most_common()
            # print str(datetime.now()), str(packet[Dot11].addr2), str(packet.type), str(packet.subtype)
            macs[packet[Dot11].addr2] = datetime.datetime.now()


def run_pusher(frequency, time_window):

    while True:
        macs_window = []
        for mac,ts in macs.iteritems():
            if ts < datetime.datetime.now()-datetime.timedelta(seconds=time_window):
                macs_window.append(mac)
            print macs_window

            sleep(frequency)


if __name__ == '__main__':
    iface = sys.argv[1]
    frequency = int(sys.argv[2])   # seconds
    time_window = int(sys.argv[3]) # seconds

    thread = Thread(target = run_sniffer)
    thread.start()

    thread2 = Thread(target = run_pusher, args = (frequency, time_window))
    thread2.start()

    thread.join()
    thread2.join()
    print "thread finished...exiting"

