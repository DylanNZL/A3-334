//////////////////////////////////////////////////////////////////////////////////////////////
// TCP CrossPlatform SERVER v.1.0 (towards IPV6 ready)
// compiles using GCC
//
//
// References: https://msdn.microsoft.com/en-us/library/windows/desktop/ms738520(v=vs.85).aspx
//             http://long.ccaba.upc.edu/long/045Guidelines/eva/ipv6.html#daytimeServer6
//             Andre Barczak's tcp server codes
//
// Author: Napoleon Reyes, Ph.D.
//         Massey University, Albany
//
//////////////////////////////////////////////////////////////////////////////////////////////

#define USE_IPV6 true

#if defined __unix__ || defined __APPLE__
  #include <unistd.h>
  #include <errno.h>
  #include <stdlib.h>
  #include <stdio.h>
  #include <string.h>
  #include <sys/types.h>  //// Structures and functions used for socket API
  #include <sys/socket.h> // Structures and functions used for socket API
  #include <arpa/inet.h>
  #include <netdb.h>      //used for domain/DNS hostname lookup (e.g getnameinfo())
  #include <iostream>
#elif defined _WIN32
  #define _WIN32_WINNT 0x501
  #include <winsock2.h>
  #include <ws2tcpip.h> //required by getaddrinfo() and special constants
  #include <stdlib.h>
  #include <stdio.h>
  #include <time.h>
  #include <iostream>
  #define WSVERS MAKEWORD(2,2) /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
                    //The high-order byte specifies the minor version number;
                    //the low-order byte specifies the major version number.

  WSADATA wsadata; //Create a WSADATA object called wsadata.
#endif
//////////////////////////////////////////////////////////////////////////////////////////////
#define SECRET_PASSWORD "334"
#define DEFAULT_PORT "1234"
using namespace std;
//*******************************************************************
void printBuffer(const char *header, char *buffer){
  cout << "------" << header << "------" << endl;
  for(unsigned int i=0; i < strlen(buffer); i++){
    if(buffer[i] == '\r'){
       cout << "buffer[" << i << "]=\\r" << endl;
    } else if(buffer[i] == '\n'){
       cout << "buffer[" << i << "]=\\n" << endl;
    } else {
       cout << "buffer[" << i << "]=" << buffer[i] << endl;
    }
  }
  cout << "---" << endl;
}
//*******************************************************************
void decryptBuffer(char * buffer, long RSA_D, long RSA_N, long RSA_NONCE) {
  cout << "Encrypted: " << buffer << endl;
  long buf[100];
  char * pch;
  char * b[100];
  pch = strtok(buffer, ":");
  int len = 0;
  while (true) {
    pch = strtok(buffer, ";");
    if (pch == NULL) {
      break;
    }
    len++;
  }

  for (int i = 0; i < len; i++) {
    buf[i] = atoi(b[i]);
    buf[i] = buf[i] % RSA_D;
    if (i == 0) { buf[i] = buf[i] % RSA_NONCE; }
    else { buf[i] = buf[i] ^ buf[i-1]; }
  } 
  char * temp_buffer = new char[200];
	memset(&temp_buffer, 200, 0);
	memset(&buffer, len, 0);
  for (int i = 0; i < len; i++) {
    sprintf(temp_buffer,"%ld", buf[i]);
    strcat(buffer, temp_buffer);
  }

  cout << "Decrypted: " << buffer << endl;
}
//*******************************************************************
//MAIN
//*******************************************************************
int main(int argc, char *argv[]) {
//********************************************************************
// INITIALIZATION of the SOCKET library
//********************************************************************
  //struct sockaddr_in clientAddress;  //IPV4
	struct sockaddr_storage clientAddress; //IPV6-compatible
	char clientHost[NI_MAXHOST];
	char clientService[NI_MAXSERV];
#if defined __unix__ || defined __APPLE__
  int s, ns;
#elif defined _WIN32
  SOCKET s, ns;
#endif
#define BUFFER_SIZE 200
  char send_buffer[BUFFER_SIZE],receive_buffer[BUFFER_SIZE];
  int  n,bytes,addrlen;
	char portNum[NI_MAXSERV];
	char username[80];
	char passwd[80];

  memset(&send_buffer,0,BUFFER_SIZE);
  memset(&receive_buffer,0,BUFFER_SIZE);

#if defined __unix__ || defined __APPLE__
   //nothing to do here
#elif defined _WIN32
//********************************************************************
// WSSTARTUP
//********************************************************************
   int err;
   err = WSAStartup(WSVERS, &wsadata);
   if (err != 0) {
      WSACleanup();
    /* Tell the user that we could not find a usable */
    /* Winsock DLL.                                  */
      printf("WSAStartup failed with error: %d\n", err);
      exit(1);
   }
  printf("\n\n<<<TCP (CROSS-PLATFORM, IPv6-ready) SERVER, by nhreyes>>>\n");
    if (LOBYTE(wsadata.wVersion) != 2 || HIBYTE(wsadata.wVersion) != 2) {
        /* Tell the user that we could not find a usable */
        /* WinSock DLL.                                  */
        printf("Could not find a usable version of Winsock.dll\n");
        WSACleanup();
        exit(1);
    }
    else{
        printf("\nThe Winsock 2.2 dll was initialised.\n");
    }

#endif


//********************************************************************
// set the socket address structure.
//********************************************************************
struct addrinfo *result = NULL;
struct addrinfo hints;
// struct addrinfo *ptr = NULL;
int iResult;

//********************************************************************
// STEP#0 - Specify server address information and socket properties
//********************************************************************

//ZeroMemory(&hints, sizeof (hints)); //alternatively, for Windows only
memset(&hints, 0, sizeof(struct addrinfo));

if(USE_IPV6){
   hints.ai_family = AF_INET6;
}	 else { //IPV4
   hints.ai_family = AF_INET;
}

//hints.ai_family = AF_UNSPEC; // don't care IPv4 or IPv6
hints.ai_socktype = SOCK_STREAM;
hints.ai_protocol = IPPROTO_TCP;
hints.ai_flags = AI_PASSIVE; // For wildcard IP address
                             //setting the AI_PASSIVE flag indicates the caller intends to use
									           //the returned socket address structure in a call to the bind function.

// Resolve the local address and port to be used by the server
if(argc==2){
	 iResult = getaddrinfo(NULL, argv[1], &hints, &result); //converts human-readable text strings representing hostnames or IP addresses
	                                                        //into a dynamically allocated linked list of struct addrinfo structures
																			                    //IPV4 & IPV6-compliant
	 sprintf(portNum,"%s", argv[1]);
	 printf("\nargv[1] = %s\n", argv[1]);

} else {
   iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result); //converts human-readable text strings representing hostnames or IP addresses
	                                                             //into a dynamically allocated linked list of struct addrinfo structures
																				                       //IPV4 & IPV6-compliant
	 sprintf(portNum,"%s", DEFAULT_PORT);
	 printf("\nUsing DEFAULT_PORT = %s\n", portNum);
}

if (iResult != 0) {
    printf("getaddrinfo failed: %d\n", iResult);

#if defined _WIN32
    WSACleanup();
#endif
    return 1;
}


//********************************************************************

//********************************************************************
// STEP#1 - Create welcome SOCKET
//********************************************************************


#if defined __unix__ || defined __APPLE__
  s = -1;
#elif defined _WIN32
  s = INVALID_SOCKET;
#endif


// Create a SOCKET for the server to listen for client connections

s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

#if defined __unix__ || defined __APPLE__
  if (s < 0) {
      printf("socket failed\n");
      freeaddrinfo(result);
      exit(1);
  }
#elif defined _WIN32
  //check for errors in socket allocation
  if (s == INVALID_SOCKET) {
      printf("Error at socket(): %d\n", WSAGetLastError());
      freeaddrinfo(result);
      WSACleanup();
      exit(1);//return 1;
  }
#endif
//********************************************************************
//********************************************************************
//STEP#2 - BIND the welcome socket
//********************************************************************

// bind the TCP welcome socket to the local address of the machine and port number
   iResult = bind( s, result->ai_addr, (int)result->ai_addrlen);


//if error is detected, then clean-up
#if defined __unix__ || defined __APPLE__
   if (iResult == -1) {
      printf( "\nbind failed\n");
      freeaddrinfo(result);
      close(s);//close socket
#elif defined _WIN32
    if (iResult == SOCKET_ERROR) {
      printf("bind failed with error: %d\n", WSAGetLastError());
      freeaddrinfo(result);
      closesocket(s);
      WSACleanup();
#endif
      return 1;
    }

	 freeaddrinfo(result); //free the memory allocated by the getaddrinfo
	                       //function for the server's address, as it is
	                       //no longer needed
//********************************************************************

/*
   if (bind(s,(struct sockaddr *)(&localaddr),sizeof(localaddr)) == SOCKET_ERROR) {
      printf("Bind failed!\n");
   }
*/

//********************************************************************
//STEP#3 - LISTEN on welcome socket for any incoming connection
//********************************************************************

#if defined __unix__ || defined __APPLE__
    if (listen( s, 5) == -1) {
#elif defined _WIN32
    if (listen( s, SOMAXCONN ) == SOCKET_ERROR ) {
#endif

#if defined __unix__ || defined __APPLE__
      printf( "\nListen failed\n");
      close(s);
#elif defined _WIN32
      printf( "Listen failed with error: %d\n", WSAGetLastError() );
      closesocket(s);
      WSACleanup();
#endif
    exit(1);

   } else {
		  printf("\n<<<SERVER>>> is listening at PORT: %s\n", portNum);
	 }

//*******************************************************************
//INFINITE LOOP
//********************************************************************
while (1) {  //main loop

      addrlen = sizeof(clientAddress); //IPv4 & IPv6-compliant

//********************************************************************
//NEW SOCKET newsocket = accept
//********************************************************************
#if defined __unix__ || defined __APPLE__
       ns = -1;
#elif defined _WIN32
       ns = INVALID_SOCKET;
#endif

//********************************************************************
// STEP#4 - Accept a client connection.
//	accept() blocks the iteration, and causes the program to wait.
//	Once an incoming client is detected, it returns a new socket ns
// exclusively for the client.
// It also extracts the client's IP address and Port number and stores
// it in a structure.
//********************************************************************
#if defined __unix__ || defined __APPLE__
      ns = accept(s,(struct sockaddr *)(&clientAddress),(socklen_t*)&addrlen); //IPV4 & IPV6-compliant
#elif defined _WIN32
      ns = accept(s,(struct sockaddr *)(&clientAddress),&addrlen); //IPV4 & IPV6-compliant
      // ns = accept(s,NULL, NULL); //IPV4 & IPV6-compliant - getnameinfo() will complain if you use this!
#endif

#if defined __unix__ || defined __APPLE__
  if (ns == -1) {
     printf("\naccept failed\n");
     close(s);
     return 1;
  } else {
      printf("\nA <<<CLIENT>>> has been accepted.\n");
      // strcpy(clientHost,inet_ntoa(clientAddress.sin_addr)); //IPV4
      // sprintf(clientService,"%d",ntohs(clientAddress.sin_port)); //IPV4
      // ---
      int returnValue;
      memset(clientHost, 0, sizeof(clientHost));
      memset(clientService, 0, sizeof(clientService));

      returnValue = getnameinfo((struct sockaddr *)&clientAddress, addrlen,
                    clientHost, sizeof(clientHost),
                    clientService, sizeof(clientService),
                    NI_NUMERICHOST);
      if(returnValue != 0){
        printf("\nError detected: getnameinfo() failed \n");
        exit(1);
      } else{
        printf("\nConnected to <<<CLIENT>>> with IP address:%s, at Port:%s\n",clientHost, clientService);
      }

  }


#elif defined _WIN32

  if (ns == INVALID_SOCKET) {
     printf("accept failed: %d\n", WSAGetLastError());
     closesocket(s);
     WSACleanup();
     return 1;

  } else {
    printf("\nA <<<CLIENT>>> has been accepted.\n");

    //strcpy(clientHost,inet_ntoa(clientAddress.sin_addr)); //IPV4
    //sprintf(clientService,"%d",ntohs(clientAddress.sin_port)); //IPV4
    //---

    DWORD returnValue;
    memset(clientHost, 0, sizeof(clientHost));
    memset(clientService, 0, sizeof(clientService));

    returnValue = getnameinfo((struct sockaddr *)&clientAddress, addrlen,
                    clientHost, sizeof(clientHost),
                    clientService, sizeof(clientService),
                    NI_NUMERICHOST);
    if(returnValue != 0){
       printf("\nError detected: getnameinfo() failed with error#%d\n",WSAGetLastError());
       exit(1);
    } else{
       printf("\nConnected to <<<Client>>> with IP address:%s, at Port:%s\n",clientHost, clientService);
    }

  }
#endif
//********************************************************************
//Communicate with the Client
//********************************************************************
		printf("\n--------------------------------------------\n");
	  printf("the <<<SERVER>>> is waiting to receive commands.\n");
		//Clear user details
		memset(username,0,80);
		memset(passwd,0,80);
    long RSA_E = 3;
    long RSA_D = 16971;
    long RSA_N = 25777;
    long RSA_NONCE = 0;
    bool acknowledged = false;

    while (1) {
         memset(receive_buffer, 0, BUFFER_SIZE);
         n = 0;
//********************************************************************
//RECEIVE one command (delimited by \r\n)
//********************************************************************
         while (1) {
            bytes = recv(ns, &receive_buffer[n], 1, 0);
#if defined __unix__ || defined __APPLE__
            if ((bytes == -1) || (bytes == 0)) break;
#elif defined _WIN32
            if ((bytes == SOCKET_ERROR) || (bytes == 0)) break;
#endif
            if (receive_buffer[n] == '\n') { /*end on a LF, Note: LF is equal to one character*/
               receive_buffer[n] = '\0';
               break;
            }
            if (receive_buffer[n] != '\r') n++; /*ignore CRs*/
         }
//this will handle the case when the user quits (types '.')
#if defined __unix__ || defined __APPLE__
      if ((bytes == -1) || (bytes == 0)) break;
#elif defined _WIN32
      if ((bytes == SOCKET_ERROR) || (bytes == 0)) break;
 #endif

//********************************************************************
//PROCESS REQUEST
//********************************************************************
    printf("\nMSG RECEIVED <<<--- :%s\n",receive_buffer);
    // TODO: Check what kind of message we recieved.
    // REQUESTING RSA E,N
    if (strncmp(receive_buffer, "SEND RSA", 8) == 0) {
      memset(&send_buffer, 0, BUFFER_SIZE);
      sprintf(send_buffer, "RSA E:%ld;N:%ld;\r\n", RSA_E, RSA_N);
    } 
    // ACKNOWLEDGE RSA E,N
    else if (strncmp(receive_buffer, "RSA ACK", 7) == 0) {
        acknowledged = true;
    } 
    // RECIEVE NONCE
    else if (strncmp(receive_buffer, "RSA NONCE", 9) == 0) {
      char * temp_buffer = new char[strlen(receive_buffer) + 1];
      strcpy (temp_buffer, receive_buffer);
      char * pch;
      pch = strtok(temp_buffer, ":");
      pch = strtok(NULL, "\0");
      RSA_NONCE = atoi(pch);
      printf("NONCE: %ld\n", RSA_NONCE);
      memset(&send_buffer, 0, BUFFER_SIZE);
      sprintf(send_buffer, "ACK 220 nonce OK\r\n");
    } 
    // RECIEVED CYCPHER TEXT
    else if (strncmp(receive_buffer, "CYPHERTEXT", 10) == 0) {
      char * temp_buffer = new char[strlen(receive_buffer) + 1];
      strcpy (temp_buffer, temp_buffer);
      printBuffer("RECEIVE_BUFFER", temp_buffer);
      decryptBuffer(temp_buffer, RSA_D, RSA_N, RSA_NONCE);
       memset(&send_buffer, 0, BUFFER_SIZE);
      sprintf(send_buffer, "Received: %s\r\n", temp_buffer);
    } 
    // UNKNOWN
    else {
      memset(&send_buffer, 0, BUFFER_SIZE);
      sprintf(send_buffer, "The Client typed '%s' - %d bytes of information\r\n", receive_buffer, n);
    }
    //********************************************************************
    // SEND
    //********************************************************************
			   bytes = send(ns, send_buffer, strlen(send_buffer), 0);
#if defined __unix__ || defined __APPLE__
         if ((bytes == -1) || (bytes == 0)) break;
#elif defined _WIN32
         if ((bytes == SOCKET_ERROR) || (bytes == 0)) break;
#endif
			   printf("\nMSG SENT     --->>> :%s\n",send_buffer);
         memset(&send_buffer,0,BUFFER_SIZE);
  }// RECV LOOP
//********************************************************************
//CLOSE SOCKET
//********************************************************************

#if defined __unix__ || defined __APPLE__
      close(ns);
#elif defined _WIN32
      iResult = shutdown(ns, SD_SEND);
      if (iResult == SOCKET_ERROR) {
         printf("shutdown failed with error: %d\n", WSAGetLastError());
         closesocket(ns);
         WSACleanup();
         exit(1);
      }
//***********************************************************************
      closesocket(ns);
#endif

      printf("\nDisconnected from <<<CLIENT>>> with IP address:%s, Port:%s\n",clientHost, clientService);
		  printf("=============================================");

    } //main loop
//***********************************************************************
#if defined __unix__ || defined __APPLE__
    close(s);//close listening socket
#elif defined _WIN32
    closesocket(s);//close listening socket
    WSACleanup(); /* call WSACleanup when done using the Winsock dll */
#endif
    return 0;
}


