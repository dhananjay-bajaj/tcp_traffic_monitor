#Sniffs incoming TCP packet
import socket, sys, struct

#create an INET, RAW socket
try:
	s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error as error:
	print('Socket could not be created. Error: ')
	print(error)
	sys.exit()

print("Source IP address | Source port number | Dest. port number | Packet number | Sequence No. | Acknowledgement No.")    #making the heading for packet information to be displayed

reg=set()
counter=dict()

#start receiving packets
while True:
    packet=s.recvfrom(65565)
	
    #packet string from tuple
    packet=packet[0]
	
    #first 20 bytes are the ip header
    ip_header=packet[0:20]
    
    #now unpack them to receive a tuple of every object(component) seperately
    iph=struct.unpack('!BBHHHBBH4s4s' , ip_header)
    
    version_ihl=iph[0]        #version and header length
    ihl=version_ihl & 0xF     #extracting length in last 4 bits
    iph_length=ihl * 4
    s_addr=socket.inet_ntoa(iph[8])     #converting network to host format
    
    #getting the tcp header of 20 bytes
    tcp_header=packet[iph_length:iph_length+20]
    
    #unpacking the header
    tcph=struct.unpack('!HHLLBBHHH' , tcp_header)

    source_port=tcph[0]
    dest_port=tcph[1]
    sequence=tcph[2]
    acknowledgement=tcph[3]

    if str(s_addr) in reg:
        counter[str(s_addr)]=counter[str(s_addr)]+1
    else:
        reg.add(str(s_addr))
        counter[str(s_addr)]=1
    
    print("\n"+str(s_addr)+r'       '+'\t'+str(source_port)+r'              '+'\t'+str(dest_port)+r'        '+'\t'+str(counter[str(s_addr)])+r'       '+'\t'+str(sequence)+r'      '+str(acknowledgement))
