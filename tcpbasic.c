/*
 * tcpbasic.c - Cross-platform TCP/IP basic functions
 * 
 * If NO_PRINT_ERROR definition exists: it will no print error messages
 */

#include "tcpbasic.h"

#include <stdio.h>
#include <string.h>

// ---- init / cleanup ----

int tcpbasic_init(void)
{
#ifdef _WIN32
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		#ifndef NO_PRINT_ERROR
		fprintf(stderr, "[!] WSAStartup failed\n");
		#endif
		return -1;
	}
#endif
	return 0;
}

void tcpbasic_cleanup(void)
{
#ifdef _WIN32
	WSACleanup();
#endif
}

// ---- resolve host + port string to addrinfo ----

static struct addrinfo *resolve(const char *host, const char *port)
{
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof hints);
	hints.ai_family   = AF_UNSPEC;   // accept IPv4 or IPv6
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, port, &hints, &res) != 0)
	{
		#ifndef NO_PRINT_ERROR
		fprintf(stderr, "[!] Cannot resolve %s:%s\n", host, port);
		#endif
		return NULL;
	}
	return res;
}

// ---- tcp_listen ----

sock_t tcp_listen(int port, int backlog)
{
	sock_t             ls;
	struct sockaddr_in addr;
	int                opt = 1;

	ls = socket(AF_INET, SOCK_STREAM, 0);
	if (ls == SOCK_INVALID)
	{
		#ifndef NO_PRINT_ERROR
		fprintf(stderr, "[!] socket() failed: %d\n", sock_errno);
		#endif
		return SOCK_INVALID;
	}

	// SO_REUSEADDR: allow immediate restart when new bind() withouth waiting
	setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof opt);

	memset(&addr, 0, sizeof addr);
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port        = htons((unsigned short)port);

	if (bind(ls, (struct sockaddr *)&addr, sizeof addr) == SOCK_ERR)
	{
		#ifndef NO_PRINT_ERROR
		fprintf(stderr, "[!] bind() failed on port %d: %d\n", port, sock_errno);
		#endif
		sock_close(ls);
		return SOCK_INVALID;
	}

	if (listen(ls, backlog) == SOCK_ERR)
	{
		#ifndef NO_PRINT_ERROR
		fprintf(stderr, "[!] listen() failed: %d\n", sock_errno);
		#endif
		sock_close(ls);
		return SOCK_INVALID;
	}

	return ls;
}

// ---- tcp_accept ----

sock_t tcp_accept(sock_t              listen_sock,
				  struct sockaddr_in *peer_addr,
				  socklen_t          *peer_addr_len)
{
	struct sockaddr_in tmp_addr;
	socklen_t          tmp_len = sizeof tmp_addr;

	// Use local temporaries if the caller does not want the peer address
	if (!peer_addr)     peer_addr     = &tmp_addr;
	if (!peer_addr_len) peer_addr_len = &tmp_len;

	sock_t conn = accept(listen_sock,(struct sockaddr*)peer_addr, peer_addr_len);
	if (conn == SOCK_INVALID)
	{
		#ifndef NO_PRINT_ERROR
		fprintf(stderr, "[!] accept() failed: %d\n", sock_errno);
		#endif
	}
	return conn;
}

// ---- tcp_connect ----

sock_t tcp_connect(const char *host, const char *port)
{
	struct addrinfo *res = resolve(host, port);
	if (!res) return SOCK_INVALID;

	sock_t s = SOCK_INVALID;
	struct addrinfo *p;
	for (p = res; p; p = p->ai_next)
	{
		s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (s == SOCK_INVALID) continue;
		if (connect(s, p->ai_addr, (socklen_t)p->ai_addrlen) == 0) break;
		sock_close(s);
		s = SOCK_INVALID;
	}
	freeaddrinfo(res);

	if (s == SOCK_INVALID)
	{
		#ifndef NO_PRINT_ERROR
		fprintf(stderr, "[!] connect to %s:%s failed: %d\n",
				host, port, sock_errno);
		#endif
	}
	return s;
}

// ---- tcp_send_all ----

int tcp_send_all(sock_t s, const void *buf, int len)
{
	const char *p = (const char *)buf;
	int sent = 0;
	while (sent < len)
	{
		int w = (int)send(s, &(p[sent]), len - sent, 0);
		if (w <= 0)
		{
			#ifndef NO_PRINT_ERROR
			fprintf(stderr, "[!] tcp_send_all: send error %d\n", sock_errno);
			#endif
			return -1;
		}
		sent += w;
	}
	return 0;
}

// ---- tcp_recv_all ----

int tcp_recv_all(sock_t s, void *buf, int len)
{
	char *p = (char *)buf;
	int got = 0;
	while (got < len)
	{
		int r = (int)recv(s, &(p[got]), len - got, 0);
		if (r <= 0)
		{
			#ifndef NO_PRINT_ERROR			
			if (r < 0)
				fprintf(stderr, "[!] tcp_recv_all: recv error %d\n", sock_errno);
			#endif
			return -1;
		}
		got += r;
	}
	return 0;
}

// ---- tcp_recv_any ----

int tcp_recv_any(sock_t s, void *buf, int len)
{
	int r = (int)recv(s, (char *)buf, len, 0);
	#ifndef NO_PRINT_ERROR
	if (r < 0)
		fprintf(stderr, "[!] tcp_recv_any: recv error %d\n", sock_errno);
	#endif
	return r; // 0 = peer closed cleanly, -1 = error, >0 = bytes received
}

// ---- tcp_shutdown_and_close ----
 
void tcp_shutdown_and_close(sock_t s)
{
	/* shutdown() aborts any recv() or send() blocked on this socket in
	 * another thread. On Linux, close() alone does not guarantee this.*/
#ifdef _WIN32
	shutdown(s, SD_BOTH);
#else
	shutdown(s, SHUT_RDWR);
#endif
	sock_close(s);
}
