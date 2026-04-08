/*
 * tunneltest.c - Test harness for tunnel
 *
 * Usage:
 *   Server mode (accepts connection from tunnel):
 *     tunneltest server <listen_port>
 *
 *   Client mode (connects to tunnel):
 *     tunneltest client <host> <port>
 *
 * In both modes the program:
 *   1. Establishes one TCP connection.
 *   2. Sends one random uint32_t (4 bytes, network byte order).
 *   3. Receives one uint32_t from the other side.
 *   4. Prints both values, then disconnects and exits.
 *
 * Example full-test setup on Windows (copy-paste to a bat file):
 *   start tunnel.exe 9000 127.0.0.1 9001 1
 *   start tunnel.exe 9001 127.0.0.1 9002 2
 *   start tunneltest.exe server 9002
 *   start tunneltest.exe client 127.0.0.1 9000
 *
 * Build:
 *   Linux : gcc tunneltest.c tcpbasic.c -o tunneltest
 *   Windows: gcc tunneltest.c tcpbasic.c -o tunneltest.exe -lws2_32
 */

#include "tcpbasic.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// ---- Simple random seed (both for Win/Linux ) ----
/* Please do not forget that the goal is not a secure pseudo random
 * number generation, but just only generate a number for testing */
#ifdef _WIN32
#	include <time.h>
	static unsigned int get_seed(void) {
		return (unsigned int)time(NULL) ^ (unsigned int)GetCurrentProcessId();
	}
#else
#	include <time.h>
#	include <fcntl.h>
	static unsigned int get_seed(void) {
		unsigned int s = 0;
		int fd = open("/dev/urandom", O_RDONLY);
		if (fd >= 0) { (void)read(fd, &s, sizeof s); close(fd); }
		if (s == 0) s = (unsigned int)time(NULL) ^ (unsigned int)getpid();
		return s;
	}
#endif

// ---- exchange: send our data, receive other side data ----
static int do_exchange(sock_t conn, const char *role)
{
	uint32_t mine   = (uint32_t)rand();
	uint32_t theirs = 0;
	printf("[%s] Sending  : %10u  (0x%08X)\n", role, mine, mine);

	// Transmit in network (big-endian) byte order so it works across
	// mixed-endian platforms (if sombody would test it in very different platforms)
	uint32_t wire_out = htonl(mine);
	if (tcp_send_all(conn, &wire_out, (int)sizeof wire_out) != 0) {
		fprintf(stderr, "[%s] send failed\n", role);
		return -1;
	}

	uint32_t wire_in = 0;
	if (tcp_recv_all(conn, &wire_in, (int)sizeof wire_in) != 0) {
		fprintf(stderr, "[%s] recv failed (or remote closed)\n", role);
		return -1;
	}
	theirs = ntohl(wire_in);
	printf("[%s] Received : %10u  (0x%08X)\n", role, theirs, theirs);

	//testing with some string too, just to make sure, it works
	char* str = "Test character string with some text for testing longer messages too.";

	char buf[256];
	memcpy(buf, str, strlen(str)+1);

	printf("[%s] Sending  : %s\n", role, buf);
	if (tcp_send_all(conn, buf, (int)strlen(str) + 1) != 0) 
	{
		fprintf(stderr, "[%s] send failed\n", role);
		return -1;
	}

	if (tcp_recv_all(conn, buf, (int)strlen(str) + 1) != 0)
	{
		fprintf(stderr, "[%s] recv failed (or remote closed)\n", role);
		return -1;
	}
	printf("[%s] Received : %s\n", role, buf);

	// OK, finish
	return 0;
}

// ---- server mode ----
static int run_server(int port)
{
	sock_t ls = tcp_listen(port, 1);
	if (ls == SOCK_INVALID) return 1;

	printf("[server] Listening on port %d - waiting for tunnel to connect...\n", port);

	struct sockaddr_in peer;
	socklen_t          peer_len = sizeof peer;
	sock_t conn = tcp_accept(ls, &peer, &peer_len);
	sock_close(ls); // one connection only; stop listening immediately

	if (conn == SOCK_INVALID) return 1;

	printf("[server] Connection from %s:%d\n",
	       inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));

	int rc = do_exchange(conn, "server");
	sock_close(conn);
	printf("[server] Done.\n");
	return rc == 0 ? 0 : 1;
}

// ---- client mode ----
static int run_client(const char *host, const char *port)
{
	sock_t s = tcp_connect(host, port);
	if (s == SOCK_INVALID) return 1;

	printf("[client] Connected to %s:%s\n", host, port);

	int rc = do_exchange(s, "client");
	sock_close(s);
	printf("[client] Done.\n");
	return rc == 0 ? 0 : 1;
}

// ---- main ----
int main(int argc, char *argv[])
{
	if (tcpbasic_init() != 0) return 1;

	srand(get_seed());

	int rc = 1;

	if (argc == 3 && strcmp(argv[1], "server") == 0)
	{
		rc = run_server(atoi(argv[2]));

	} else if (argc == 4 && strcmp(argv[1], "client") == 0) 
	{
		rc = run_client(argv[2], argv[3]);
	} 
	else
	{
		fprintf(stderr,
			"Usage:\n"
			"  %s server <listen_port>\n"
			"  %s client <host> <port>\n"
			"\n"
			"Very simple setup (three terminals):\n"
			"  1. tunnel 9000  127.0.0.1 9002 0\n"
			"  2. %s server 9002\n"
			"  3. %s client 127.0.0.1 9000\n",
			argv[0], argv[0], argv[0], argv[0]);
	}

	tcpbasic_cleanup();
	printf("Press Enter to Exit!");
	int ch = getchar();
	return rc;
}
