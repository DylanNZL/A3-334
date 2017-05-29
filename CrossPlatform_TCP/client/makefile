client.exe		: 	client.o 
	g++ -Wall -O2 client.cpp -lws2_32 -o client.exe 
			
client.o		:	client.cpp 
	g++ -c -O2 -Wall client.cpp
	
clean:
	del *.o
	del *.exe