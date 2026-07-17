from scapy.all import sniff, IP, TCP
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

    #acts as a handler for each captured packets
    #checks if packets have IP or TCP layers
    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def start_capture(self, interface="wlp1s0"):
        def capture_thread():
            sniff(iface=interface,
                  prn=self.packet_callback,
                  store=0,
                  stop_filter=lambda _: self.stop_capture.is_set())
        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()