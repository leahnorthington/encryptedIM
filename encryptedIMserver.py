import socket, select

listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listen_socket.bind(("", 9999)) 
listen_socket.listen(10)       # specify the "backlog" for this socket

connected_clients = []


while True:
    read_list = [listen_socket] + connected_clients
    (ready_list,_,_) = select.select(read_list,[],[])
    for ready in ready_list:
        if ready is listen_socket:
            conn, addr = ready.accept()        # accept the connection
            print( "Got a newconnection from", addr )
            connected_clients += [conn]
        else:
            try:
                data = ready.recv(1024)
                if len(data) == 0:
                    print( "A client went bye-bye" )
                    connected_clients.remove(ready)
                else:
                    print( "Got some data ('%s') from a client" % data.rstrip() )
                    for other_socket in connected_clients:
                        if other_socket == ready: continue
                        other_socket.send(data)
            except ConnectionResetError:
                connected_clients.remove(ready)

                                                                            
