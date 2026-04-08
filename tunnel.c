/*
 * tunnel.c - TCP relay-proxy with encryption
 *
 * Usage:
 *   tunnel <listen_port> <remote_host> <remote_port> <role> <opt. password>
 *
 * Behaviour:
 *   1. Binds <listen_port> and waits for exactly one incoming client (A).
 *   2. Connects to <remote_host>:<remote_port> (socket B).
 *   3. Relays all bytes A->B and B->A concurrently (encoded if role=1/2).
 *   4. If either side closes / errors, both sockets are closed and the
 *      program loops back to step 1. 
 *
 * Build:
 *   Windows: gcc tunnel.c tcpbasic.c manochiper.c -o tunnel.exe -lws2_32 -lbcrypt
 *   Linux:   gcc tunnel.c tcpbasic.c manochiper.c -o tunnel -D_GNU_SOURCE
 *
 * Do not forget about NO_PRINT_ERROR / NO_PRINT_INFO definitions!
 */

#include "tcpbasic.h"
/* 
 * Note: NO_PRINT_ERROR and NO_PRINT_INFO (if used) shall be defined in tcpbasic.h!
 */
#include "manochiper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//-------- threading: platform dependent --------
#ifdef _WIN32
	#define THREAD_RET    DWORD WINAPI
	#define THREAD_HANDLE HANDLE
	static HANDLE thread_create(LPTHREAD_START_ROUTINE fn, void *arg) {
		return CreateThread(NULL, 0, fn, arg, 0, NULL);
	}
	#define thread_join(h) WaitForSingleObject(h, INFINITE)
#else
	#include <pthread.h>
	#define THREAD_RET    void *
	#define THREAD_HANDLE pthread_t
	static pthread_t thread_create(void *(*fn)(void *), void *arg) {
		pthread_t t;
		pthread_create(&t, NULL, fn, arg);
		return t;
	}
	#define thread_join(h) pthread_join(h, NULL)
#endif

//-------- Constant definitions --------
#define BUF_SIZE  4096  // TCP buffer size in bytes
#define BACKLOG   1     // listen() backlog - we only want one client

#define ROLE_NONE 0     // tunnel has no special role, no encryption
#define ROLE_CLIENT 1   // client side tunnel with encryption
#define ROLE_SERVER 2   // server side tunnel with encryption

#define ROLE_ENCODE 1   // relay thread encodes (sending to other tunnel)
#define ROLE_DECODE 2   // relay thread decodes (sending to remote side)

//-------- Data types --------

// Input data structure for the working threads
typedef struct {
	sock_t src;  // read from here
	sock_t dst;  // write to here
	int    role; // encode/decode role of thread
} relay_args_t;

//-------- Main memory resident variables --------

// Secret (scrambled) password used encoder/decoder threads for chipers
static char psw[256];

//----- Main functions -----

// Working thread: One-direction relay thread with encryption
static THREAD_RET relay_thread(void *arg)
{
	relay_args_t *r = (relay_args_t *)arg;
	
	// Buffer for receiving and sending
	char* buf = malloc(BUF_SIZE);
	if (buf == NULL) goto _finish;
	
	// Session chiper for this relay
	ChiperData *chiper = calloc(1, sizeof(ChiperData));
	if (chiper == NULL) goto _finish;

	// Encoder relay: Initialize chiper and send the salt to other relay
	if (r->role == ROLE_ENCODE)
	{
		#ifndef NO_PRINT_INFO
		printf("[thread %i] sending new session chiper...\n",r->role);
		#endif
		// generate random salt (it is the session key)
		uint8_t salt[CHIPER_SALT_BYTES];
		if (ChiperGenerateSalt(salt) < 0) goto _finish;
		// initialize the chiper (salt + password) in CTR mode
		if (ChiperInit(chiper, psw, 256, salt, CHIPER_MODE_CTR) < 0) goto _finish;
		// send salt to other tunnel
		if (tcp_send_all(r->dst, salt, CHIPER_SALT_BYTES) != 0) goto _finish;
	}

	// Decoder relay: Initialize chiper with received salt from other relay
	if (r->role == ROLE_DECODE)
	{
		#ifndef NO_PRINT_INFO
		printf("[thread %i] wait for session chiper...\n",r->role);
		#endif
		// recieve the salt from other tunnel
		uint8_t salt[CHIPER_SALT_BYTES];
		if (tcp_recv_all(r->src, salt, CHIPER_SALT_BYTES) != 0) goto _finish;
		// initialize the chiper (salt + password) in CTR mode
		if (ChiperInit(chiper, psw, 256, salt, CHIPER_MODE_CTR) < 0) goto _finish;
	}
	
	#ifndef NO_PRINT_INFO
	printf("[thread %i] OK. Start relay...\n",r->role);
	#endif

	// Main loop (until sockets are closed/destroyed)
	while (1)
	{
		// Receiving from source
		int n = tcp_recv_any(r->src, buf, BUF_SIZE);
		if (n <= 0)
		{
			#ifndef NO_PRINT_INFO
			printf("[thread %i] tcp_recv_any error - break\n",r->role);
			#endif
			break;
		}

		// Encode/decode the received data (same algorithm)
		if (r->role != ROLE_NONE)
			ChiperStreamEncode(chiper, buf, n);

		// Sending it to destination
		if (tcp_send_all(r->dst, buf, n) != 0)
		{
			#ifndef NO_PRINT_INFO
			printf("[thread %i] tcp_send_all error - break\n",r->role);
			#endif
			break;
		}
	}

_finish:
	#ifndef NO_PRINT_INFO
	printf("[thread %i] Thread ending (closing sockets...)\n",r->role);
	#endif
	/* Closing both sockets to unblock the other thread (waiting in tcp_recv/tcp_send).
	 * Note that closing again a closed socket is harmless.
	 * Unider Linux closing is not enough, so we shutdown it too. */
	tcp_shutdown_and_close(r->src);
	tcp_shutdown_and_close(r->dst);
	
	// Free allocated memories
	if (chiper != NULL) free(chiper);
	if (buf != NULL) free(buf);
	free(r);

#ifdef _WIN32
	return 0;
#else
	return NULL;
#endif
}


// Start two working threads and wait for them to finish
static void run_threads(sock_t a, sock_t b, int role)
{
	// Input configuration for a->b relay
	relay_args_t *ab = malloc(sizeof *ab);
	if (ab == NULL) return;
	ab->src = a;
	ab->dst = b;
	
	// Input configuration for b->a relay
	relay_args_t *ba = malloc(sizeof *ba);
	if (ba == NULL) {free(ab); return;}
	ba->src = b;
	ba->dst = a;

	// Encode/decode configuration
	switch (role) {
	 case ROLE_CLIENT:
		ab->role = ROLE_ENCODE;
		ba->role = ROLE_DECODE;
		break;
	 case ROLE_SERVER:
		ab->role = ROLE_DECODE;
		ba->role = ROLE_ENCODE;
		break;
	 default:
		ab->role = ROLE_NONE;
		ba->role = ROLE_NONE;		
	}

	// Create and start the threads
	THREAD_HANDLE t1 = thread_create(relay_thread, ab);
	THREAD_HANDLE t2 = thread_create(relay_thread, ba);

	// Wait until both threads terminated
	thread_join(t1);
	thread_join(t2);

	// relay_args are freed inside relay_thread, so nothing to do
	return;
}


//-------- MAIN --------
int main(int argc, char *argv[])
{
	if (argc < 1+4)
	{
		fprintf(stderr, "Usage: %s <listen_port> <remote_host> <remote_port> <role> <optional psw>\n",
				argv[0]);
		fprintf(stderr, "Example: %s 8080 example.com 80 1\n", argv[0]);
		return 1;
	}

	int listen_port = atoi(argv[1]);
	const char *remote_host = argv[2];
	const char *remote_port = argv[3];
	int role = atoi(argv[4]);

	// Password
	memset(psw, 0, 256); // must be fill with 0 becasue the whole is used!
	if (argc >= 1+5) // if input argument
	{
		strncpy(psw, argv[5], 255);
		// delete the argument from memory (at least here, the OS / console may remember...)
		volatile char *p = (volatile char *)(argv[5]);
		size_t i;
		for (i = 0; i < strlen(argv[5]); i++) p[i] = 0;
	}
	else //or a fixed default password (I recommend to replace it for yourself)
	{
		strcpy(psw, "KlO_:,/ThjR+!dJk<@&eTU =md+?.H[fd");
	}
	// Scramble the password (null-terminated string)
	ChiperPasswordScramble(psw);

	// If no TCP working, exit
	if (tcpbasic_init() != 0) return 1;

	// Start listening
	sock_t listen_sock = tcp_listen(listen_port, BACKLOG);
	if (listen_sock == SOCK_INVALID) return 1;

	#ifndef NO_PRINT_INFO
	printf("Listening on port %d\n", listen_port);
	printf("Will connect to %s:%s\n", remote_host, remote_port);
	#endif

	// Main loop, it never breaks (? expect break by the OS ?)
	while (1)
	{
		//Step 1: wait for one client
		struct sockaddr_in client_addr;
		socklen_t client_len = sizeof client_addr;

		#ifndef NO_PRINT_INFO
		printf("Waiting for client...\n");
		#endif
		sock_t a = tcp_accept(listen_sock, &client_addr, &client_len);
		if (a == SOCK_INVALID) continue;

		#ifndef NO_PRINT_INFO
		printf("A side connected: %s:%d\n", 
			inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
		#endif

		//Step 2: connect to remote
		sock_t b = tcp_connect(remote_host, remote_port);
		if (b == SOCK_INVALID)
		{
			#ifndef NO_PRINT_ERROR
			fprintf(stderr, "Could not reach remote; dropping client.\n");
			#endif
			sock_close(a);
			continue;
		}
		#ifndef NO_PRINT_INFO
		printf("B side connected to %s:%s\n", remote_host, remote_port);
		#endif

		//Step 3: relay until one side closes
		#ifndef NO_PRINT_INFO
		printf("Session started. (Ctrl-C to stop the whole program)...\n");
		#endif
		run_threads(a, b, role);

		//Sockets are already closed by the relay threads; these are
		//just for safety that guard against any future refactoring:
		tcp_shutdown_and_close(a);
		tcp_shutdown_and_close(b);

		#ifndef NO_PRINT_INFO
		printf("Session ended. Restarting...\n");
		#endif
	}

	// Finally close listen socket and cleanup
	tcp_shutdown_and_close(listen_sock);
	tcpbasic_cleanup();

	return 0;
}
