from scapy.all import sniff, IP, TCP, ARP
from collections import defaultdict
import threading
import queue

#PACKET CAPTURE ENGINE
class packetCapture:
    def __init__(self): #initializes the class
        #stores captured packets
        self.packet_queue= queue.Queue()
        #controls when the packet capture should stop
        self.stop_capture= threading.Event()
        #an exception raised inside the sniff thread, for the main loop to see
        self.capture_error = None

    #acts as a handler for each captured packet
    #queues TCP/IP packets (for the traffic analyzer) and ARP packets (for the
    #ARP spoofing detector); the main loop routes them by type.
    def packet_callback(self, packet):
        if (IP in packet and TCP in packet) or ARP in packet:
            self.packet_queue.put(packet)

    def start_capture(self, interface="wlp1s0"):
        def capture_thread():
            # sniff() raises in this thread, where the main loop cannot see it;
            # stash it so the main loop can stop instead of polling forever.
            try:
                sniff(iface=interface,
                      prn=self.packet_callback,
                      store=0,
                      stop_filter=lambda _: self.stop_capture.is_set())
            except Exception as exc:
                self.capture_error = exc
                self.stop_capture.set()
        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()