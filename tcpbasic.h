/*
 * tcpbasic.h - Cross-platform TCP/IP basic functions
 *
 * Provides a uniform API over Winsock2 (Windows) and POSIX sockets
 * (Linux / macOS).
 *
 * All functions return -1 (or SOCK_INVALID on Windows) on failure.
 */

#ifndef TCPBASIC_H
#define TCPBASIC_H

#define NO_PRINT_ERROR  // no error messages is printed to stderr
#define NO_PRINT_INFO	// no information is printed to stdout

//-------- platform dependent includes and defines --------
#ifdef _WIN32
	#define WIN32_LEAN_AND_MEAN
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#pragma comment(lib, "ws2_32.lib")
	typedef SOCKET	sock_t;
	typedef int	socklen_t;
	#define SOCK_INVALID	INVALID_SOCKET
	#define SOCK_ERR		SOCKET_ERROR
	#define sock_close(s)	closesocket(s)
	#define sock_errno      WSAGetLastError()
#else
	#define SOCK_INVALID	(-1)
	#define SOCK_ERR		(-1)
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <netdb.h>
	#include <unistd.h>
	#include <errno.h>
	typedef int sock_t;
	#define sock_close(s)	close(s)
	#define sock_errno      errno
#endif

//-------- API --------

/*
 * tcpbasic_init / tcpbasic_cleanup
 *   Must be called once at program start and exit respectively.
 *   On Linux these are empty; on Windows they call WSAStartup/WSACleanup.
 *   tcpbasic_init returns 0 on success, -1 on failure.
 */
int  tcpbasic_init(void);
void tcpbasic_cleanup(void);

/*
 * tcp_listen
 *   Creates a TCP socket, sets SO_REUSEADDR, binds to <port>,
 *   and calls listen() with the given <backlog> number.
 *   Returns the listening socket, or SOCK_INVALID on error.
 */
sock_t tcp_listen(int port, int backlog);

/*
 * tcp_accept
 *   Blocks until one client connects to <listen_sock>.
 *   If <peer_addr> / <peer_addr_len> are non-NULL they are filled in with the
 *   remote address (same as accept()).
 *   Returns the connected socket, or SOCK_INVALID on error.
 */
sock_t tcp_accept(sock_t              listen_sock,
				  struct sockaddr_in *peer_addr,
				  socklen_t          *peer_addr_len);

/*
 * tcp_connect
 *   Resolves host:port (IPv4 or IPv6) and connects a new TCP socket.
 *   Returns the connected socket, or SOCK_INVALID on error.
 */
sock_t tcp_connect(const char *host, const char *port);

/*
 * tcp_send_all
 *   Sends exactly <len> bytes from <buf>, looping over partial sends.
 *   Returns 0 on success, -1 if the socket errors or closes mid-send.
 */
int tcp_send_all(sock_t s, const void *buf, int len);

/*
 * tcp_recv_all
 *   Receives exactly <len> bytes into <buf>, looping over partial recvs.
 *   Returns 0 on success, -1 on error or if the peer closes the connection
 *   before all bytes arrive.
 */
int tcp_recv_all(sock_t s, void *buf, int len);

/*
 * tcp_recv_any
 *   Receives whatever is available (up to <len> bytes) into <buf>.
 *   This is a single recv() call - it does not loop.
 *   Returns the number of bytes received (>0) on success,
 *   0 if the peer closed the connection cleanly,
 *   -1 on socket error.
 */
int tcp_recv_any(sock_t s, void *buf, int len);

/*
 * tcp_shutdown_and_close
 *   Shuts down both directions of <s> and then closes it.
 *   shutdown(SHUT_RDWR) is used before close() because on Linux, close()
 *   alone does not reliably unblock another thread that is sleeping inside
 *   recv() on the same socket. shutdown() is defined to abort pending I/O
 *   immediately across all threads.
 *   On Windows, closesocket() already has this property, so shutdown is
 *   still called for symmetry but is not strictly required there.
 */
void tcp_shutdown_and_close(sock_t s);

#endif // TCPBASIC_H
