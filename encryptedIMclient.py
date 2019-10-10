import argparse
import socket
import select
import encryptedIM_pb2
import sys
import struct
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hmac
import signal

def signal_handler(sig, frame):
    sys.exit(0)

def main():

    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser()
    parser.add_argument('-n', dest='nickname', help='your nickname', required=True)
    parser.add_argument('-s', dest='server', help='server', required=True)
    parser.add_argument('-p', dest='port', help='port name', required=True)
    parser.add_argument('-c', dest='conf', help='confidentiality key', required=True)
    parser.add_argument('-a', dest='auth', help='authenticity key', required=True)
    
    args = parser.parse_args()

    blockSize = 16

    # connect to server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect( (args.server,9999) )

    read_fds = [ sys.stdin, s ]

    #force the keys to be 256 bits long
    auth_key = hashlib.sha256((args.auth).encode("utf-8")).digest()
    conf_key = hashlib.sha256((args.conf).encode("utf-8")).digest()

    while True:
        (ready_list,_,_) = select.select(read_fds,[],[])
        if sys.stdin in ready_list:
            # this user has entered a message
            try: 
                user_input = input()    
            except EOFError as error:
                    exit(0)

            if user_input.rstrip().lower() == "exit":
                s.close()
                exit(0)
            
            #create basic message for nickname and user message
            basic_message = encryptedIM_pb2.basicIMmessage()

            # first set the values of the message & serialize
            basic_message.content = user_input
            basic_message.nickname = args.nickname
            serialized_basic = basic_message.SerializeToString()
            
            #nickname and message must be 16 bytes or multiple of 16 bytes
            padded_msg = pad(serialized_basic, blockSize)

            #generate random IV for each message
            iv = get_random_bytes(blockSize)

            #encrypt the padded message
            cipher1 = AES.new(conf_key, AES.MODE_CBC, iv)
            cipher_text = cipher1.encrypt(padded_msg)
            
            #compute MAC of encrypted padded message
            mac = hmac.new(auth_key, cipher_text).digest()

            #create message for IV and HMAC
            encryption_message = encryptedIM_pb2.encryptedIMmessage()
            encryption_message.iv = iv
            encryption_message.mac = mac
            encryption_message.cipherText = cipher_text
            serialized_en = encryption_message.SerializeToString()

            #send length of message w IV and HMAC
            serialized_len_en = len(serialized_en)
            s.send( struct.pack("!H", serialized_len_en ) )
            #finally send message w IV and HMAC
            s.send( serialized_en )

            #first send length of serialized message w nickname and message
            serialized_len_basic = len(serialized_basic)
            s.send( struct.pack("!H", serialized_len_basic ) )
            #then send message w nickname and message
            s.send( serialized_basic )
            
        if s in ready_list:
            # data coming from another connection
            #NEED TO AUTHENTICATE MESSAGE BEFORE READING. IF NOT, PUT ERROR MESSAGE + DON'T TERMINATE
            packed_len_en = s.recv(2,socket.MSG_WAITALL)
            unpacked_len_en = struct.unpack("!H", packed_len_en )[0]
            serialized_msg_en = s.recv(unpacked_len_en,socket.MSG_WAITALL)
            message_en = encryptedIM_pb2.encryptedIMmessage()
            message_en.ParseFromString( serialized_msg_en )
            #now message_en.iv has IV and message_en.mac has HMAC and message_en.cipherText has cipher_text
            #so now i have what i need to authenticate the message!
            test_mac = hmac.new(auth_key, (message_en.cipherText)).digest()
            if hmac.compare_digest(message_en.mac, test_mac) is False:
                # print error message
                packed_len_basic = s.recv(2,socket.MSG_WAITALL)
                unpacked_len_basic = struct.unpack("!H", packed_len_basic )[0]
                serialized_msg_basic = s.recv(unpacked_len_basic,socket.MSG_WAITALL)
                print("Unable to authenticate message. Yikes!")
            else:
                # message is good!
                packed_len_basic = s.recv(2,socket.MSG_WAITALL)
                unpacked_len_basic = struct.unpack("!H", packed_len_basic )[0]
                serialized_msg_basic = s.recv(unpacked_len_basic,socket.MSG_WAITALL)
                #decrypt serialized message
                message_basic = encryptedIM_pb2.basicIMmessage()
                message_basic.ParseFromString( serialized_msg_basic )
                cipher2 = AES.new(conf_key, AES.MODE_CBC, message_en.iv)
                cipher_text = cipher2.decrypt(message_en.cipherText)
                try:
                    unpadded = unpad(cipher_text, blockSize)
                    print( "%s: %s" % (message_basic.nickname, message_basic.content), flush=True )
                except:
                    print("Confidentiality keys do not match :(")

            

if __name__ == '__main__':
    main()
    
