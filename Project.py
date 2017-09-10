from PyQt4 import QtCore, QtGui, uic
import os 
import socket, sys
from struct import *


def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b

try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()



qtCreatorFile = "/home/saroj/Documents/osgui.ui" # Enter file here.
 
Ui_MainWindow, QtBaseClass = uic.loadUiType(qtCreatorFile)
 
class MyApp(QtGui.QMainWindow, Ui_MainWindow):
    def __init__(self):
        QtGui.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.Check.clicked.connect(self.ping)
        self.Clean.clicked.connect(self.clean)

    def clean(self):
	self.text.setPlainText("")
	self.os_text.setText("")


    def ping(self):
      res = ""
      hostname = str(self.text.toPlainText())#example
      response = os.system("ping -c 1 " + hostname)
      #and then check the response...
      if response == 0:
        print hostname, 'is up!'
      else:
        print hostname, 'is down!'
	sys.exit()
      try:
	    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
      except socket.error , msg:
	    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
      	    sys.exit()
      while True:
	    os.system("ping -c 1 " + hostname)
	    packet = s.recvfrom(65565)
            packet = packet[0]
            eth_length = 14
	    eth_header = packet[:eth_length]
	    eth = unpack('!6s6sH' , eth_header)
	    eth_protocol = socket.ntohs(eth[2])
	    if eth_protocol == 8 :
	        #Parse IP header
	        ip_header = packet[eth_length:20+eth_length]	        
	        iph = unpack('!BBHHHBBH4s4s' , ip_header)	 
	        version_ihl = iph[0]
	        version = version_ihl >> 4
	        ihl = version_ihl & 0xF 
	        iph_length = ihl * 4 
	        ttl = iph[5]
	        protocol = iph[6]
	        s_addr = socket.inet_ntoa(iph[8]);
	        d_addr = socket.inet_ntoa(iph[9]);
	 	if str(s_addr)==hostname:      
			print 'ttl : ' + str(ttl)
			if ttl <= 64 :
				res = 'Guess :::Its a Linux OS' 
			else:
				res = 'Guess :::Its a Windows OS'
			#sys.exit()
                        break
	        	 
	        #TCP protocol
	        if protocol == 6 :
	            t = iph_length + eth_length
	            tcp_header = packet[t:t+20]	            
	            tcph = unpack('!HHLLBBHHH' , tcp_header)	             
	            source_port = tcph[0]
	            dest_port = tcph[1]
	            sequence = tcph[2]
	            acknowledgement = tcph[3]
	            doff_reserved = tcph[4]
	            tcph_length = doff_reserved >> 4	             
	            h_size = eth_length + iph_length + tcph_length * 4
	            data_size = len(packet) - h_size	            
	            data = packet[h_size:]	           
	 
	        #ICMP Packets
	        elif protocol == 1 :
	            u = iph_length + eth_length
	            icmph_length = 4
	            icmp_header = packet[u:u+4]	 
	            icmph = unpack('!BBH' , icmp_header)	             
	            icmp_type = icmph[0]
	            code = icmph[1]
	            checksum = icmph[2]	             
	            h_size = eth_length + iph_length + icmph_length
	            data_size = len(packet) - h_size            
	            data = packet[h_size:]	             
	           	 
	        #UDP packets
	        elif protocol == 17 :
	            u = iph_length + eth_length
	            udph_length = 8
	            udp_header = packet[u:u+8]	 
	            udph = unpack('!HHHH' , udp_header)	             
	            source_port = udph[0]
	            dest_port = udph[1]
	            length = udph[2]
	            checksum = udph[3]
	             
	            h_size = eth_length + iph_length + udph_length
	            data_size = len(packet) - h_size	            
	            data = packet[h_size:]          
	 
	        else :
	            print ''#'Protocol other than TCP/UDP/ICMP'
        
      self.os_text.setText(res)
	 
if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    window = MyApp()
    window.show()
    sys.exit(app.exec_())
