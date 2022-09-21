message_ssh: message_ssh.o
	gcc message_ssh.o -lssl -lcrypto -o message_ssh

message_ssh.o: message_ssh.c
	gcc -c message_ssh.c
clean:
	rm *.o output
