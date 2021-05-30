cc = g++

server : ./src/server/server.cpp ./src/server/server.h ./src/protocol/pdu.h ./src/protocol/dfa.h
	$(cc) -oserver -pthread ./src/server/server.cpp -lssl -lcrypto

client: ./src/client/client.cpp ./src/client/client.h ./src/protocol/pdu.h
	$(cc) -oclient -pthread ./src/client/client.cpp -lssl -lcrypto

