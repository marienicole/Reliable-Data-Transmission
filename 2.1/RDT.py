import Network
import argparse
from time import sleep
import hashlib


class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32

    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S

    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(seq_num, msg_S)


    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S


    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length :]

        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S


class RDT:
    ## latest sequence number used in a packet
    seq_num = 1
    ## buffer of bytes read from network
    byte_buffer = ''

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)

    def disconnect(self):
        self.network.disconnect()

    def is_ACK(self, response):
        if 'NAK' in response: # is a NAK, not ACK
            return False
        else: # is ACK
            return True

    def is_corrupt(self, bytes):
        if Packet.corrupt(bytes):
            return True
        else:
            return False

    def rdt_2_1_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.network.udt_send(p.get_byte_S())
        r = 'NAK'
        while 'NAK' in r or r is '':
            r = self.network.udt_receive()

            print("in SEND: R is %s" % r)

            if 'NAK' not in r or r is not '':
                break
            else:
                self.network.udt_send(p.get_byte_S())
        self.seq_num += 1

    def rdt_2_1_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        print("in RECEIVE: self.byte_buffer is %s" % self.byte_buffer)
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if self.is_corrupt(self.byte_buffer) or not self.is_ACK(self.byte_buffer):
                neg_resp = Packet(self.seq_num, "NAK") # send corrupted seq num
                print("in RECEIVE: neg_resp message is %s" % neg_resp.get_byte_S())
                self.network.udt_send(neg_resp.get_byte_S())
                continue
                #ret_s = p.msg_S

            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            print("in RECEIVE: new packet byte is %s" % p.get_byte_S())
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration
        return ret_S
       #
       #
       #
       #  ret_S = None
       #  byte_S = self.network.udt_receive()
       #  self.byte_buffer += byte_S
       #  #keep extracting packets - if reordered, could get more than one
       #  while True:
       #      #check if we have received enough bytes
       #      if(len(self.byte_buffer) < Packet.length_S_length):
       #          return ret_S #not enough bytes to read packet length
       #      #extract length of packet
       #      length = int(self.byte_buffer[:Packet.length_S_length])
       #      if len(self.byte_buffer) < length:
       #          return ret_S #not enough bytes to read the whole packet
       #      #create packet from buffer content and add to return string
       #
       #      # if packet is corrupt send which is corrupt
       #      if self.is_corrupt(self.byte_buffer) or not self.is_ACK(self.byte_buffer):
       #          neg_resp = Packet(self.seq_num, "NAK") # send corrupted seq num
       #          self.network.udt_send(neg_resp)
       #          ret_s = p.msg_S
       #
       #      elif
       #
       #      else:
       #          print("packet ok")
       #          p = Packet.from_byte_S(self.byte_buffer[0:length])
       #          ack_packet = Packet(self.seq_num, "1") # one is good!!
       #          self.network.udt_send(ack_packet.get_byte_S())
       #
       #          ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
       #      #remove the packet bytes from the buffer
       #          self.byte_buffer = self.byte_buffer[length:]
       #
       #      return ret_S
       #      #if this was the last packet, will return on the next iteration
       # # if corrupt, we send NAK
       # # if timeout, we re-send the packet?

    def rdt_3_0_send(self, msg_S):
        pass

    def rdt_3_0_receive(self):
        pass


if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_2_1_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_2_1_receive())
        rdt.disconnect()


    else:
        sleep(1)
        print(rdt.rdt_2_1_receive())
        rdt.rdt_2_1_send('MSG_FROM_SERVER')
        rdt.disconnect()
