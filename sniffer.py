from datetime import datetime
from scapy.all import *
from collections import Counter
import sys
from threading import Thread
from collections import defaultdict
import datetime
from time import sleep
import time

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
        for mac in macs.keys():
            ts = macs[mac]
            if ts > datetime.datetime.now()-datetime.timedelta(seconds=time_window):
                macs_window.append(mac)

        print len(macs_window)
        count = len(macs_window)

        import requests
        r = requests.post('http://datumize-iot.azurewebsites.net/metrics',
                      data=u'metric=count,ts='+unicode(int(time.time()))+u',value='+unicode(count)+u',device=test-pre')
        print r.status_code
        sleep(frequency)


if __name__ == '__main__':
    iface = sys.argv[1]
    frequency = int(sys.argv[2])   # seconds
    time_window = int(sys.argv[3]) # seconds

    thread2 = Thread(target = run_pusher, args = (frequency, time_window))
    thread2.start()

    run_sniffer()

    #thread.join()

