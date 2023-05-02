/**
 * An asynchronous, single-threaded SOCKS proxy.
 *
 * Copyright 2023 Alexandre Emsenhuber
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include <getopt.h>
#include <unistd.h>
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef ARES
#include <ares.h>

ares_channel channel;
#endif

int forward_af = AF_UNSPEC;

struct socksAddr {
	char type;
	union {
		struct sockaddr_in in4_addr;
		struct sockaddr_in6 in6_addr;
		struct {
			char host[256];
			char hostLen;
			short port;
		} dns_addr;
	} addr;
	socklen_t addr_len;
};

#ifdef ARES
struct handshake_ares_res {
	int status;
	int error;
	struct ares_addrinfo* result;
};
#endif

struct socks_connection_pair {
	int state;
	uint16_t nbytes;

	char vers;
	char hasNoAuth;
	char cmd;
	char error;

#ifdef ARES
	struct handshake_ares_res* res_ares;
	struct ares_addrinfo* res_base;
	struct ares_addrinfo_node* res_cur;
#else
	struct addrinfo* res_base;
	struct addrinfo* res_cur;
#endif

	int client_fd;
	short client_flags;
	short client_dirs;
	struct socksAddr clientFromAddr;
	// clientToAddr is useless, it is the address which we are bound to.

	int server_fd;
	short server_flags;
	short server_dirs;
	struct socksAddr serverFromAddr;
	struct socksAddr serverToAddr;

	char cts_buf[16384];
	size_t cts_len;
	char stc_buf[16384];
	size_t stc_len;
};

/**
 * Print a socksAddr to the standard output
 */
void print_sockaddr( struct socksAddr* addr ) {
	if ( addr->type == 1 ) {
		/* IPv4 */
		char buf[INET_ADDRSTRLEN];
		printf( "IPv4 %s port %hu", inet_ntop( AF_INET, &( addr->addr.in4_addr.sin_addr ), buf, INET_ADDRSTRLEN ), ntohs( addr->addr.in4_addr.sin_port ) );
	} else if ( addr->type == 3 ) {
		/* Host name */
		printf( "name %s port %hu", addr->addr.dns_addr.host, ntohs( addr->addr.dns_addr.port ) );
	} else if ( addr->type == 4 ) {
		/* IPv6 */
		char buf[INET6_ADDRSTRLEN];
		printf( "IPv6 %s port %hu", inet_ntop( AF_INET6, &( addr->addr.in6_addr.sin6_addr ), buf, INET6_ADDRSTRLEN ), ntohs( addr->addr.in6_addr.sin6_port ) );
	} else {
		printf( "invalid type %d", addr->type );
	}
}

/**
 * Accept a new client connection and mark it for handshake
 */
void socks_accept( int listen_fd, int server_family, struct socks_connection_pair* pair ) {
	memset( pair, 0, sizeof( struct socks_connection_pair ) );

	if ( server_family == PF_INET ) {
		pair->clientFromAddr.type = 1;
	} else if ( server_family == PF_INET6 ) {
		pair->clientFromAddr.type = 4;
	}

	socklen_t client_len; // Pointless but still
	pair->client_fd = accept( listen_fd, (struct sockaddr *)&pair->clientFromAddr.addr, &client_len );
	pair->server_fd = -1;

	if ( pair->client_fd == -1 ) {
		pair->state = -1;
		perror( "accept" );
		return;
	}

	/* Mark for hanshake */
	pair->state = 1;
}

/**
 * SOCKS handshake
 * ---------------
 */

#ifdef ARES
void handshake_ares_callback( void* arg, int status, int timeout, struct ares_addrinfo* result ) {
	struct handshake_ares_res* data = (struct handshake_ares_res*) arg;

	if ( data->status == -1 ) {
		/* Connection was canceled, cleanup now */
		if ( status == 0 ) ares_freeaddrinfo( result );
		free( data );
	} else {
		data->status = 1;
		data->error = status;
		if ( status == 0 ) data->result = result;
	}
}
#endif

/**
 * SOCKS server handshake
 *
 * This is fully asynchronous.
 */
int handshake_handle( struct socks_connection_pair* pair ) {
	/* state 1: first packet from client to server (version and authentication methods) */
	if ( pair->state == 1 && ( pair->client_flags & POLLIN ) ) {
		/* First byte: protocol version; we only accept SOCKS5 */
		if ( pair->vers == 0 ) {
			ssize_t n = read( pair->client_fd, &pair->vers, 1 );
			if ( n == -1 && ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ) ) return 0;
			if ( n <= 0 ) return 1;

			if ( pair->vers != 5 ) {
				fprintf( stderr, "protocol version not recognised: %d\n", (int)pair->vers );
				return 1;
			}
		}

		/* We do not accept authentication, so we only allow method "0" */
		pair->hasNoAuth = 0;

		/* Second byte: number of authentication methods */
		if ( pair->nbytes == 0 ) {
			char nmethods;
			ssize_t n = read( pair->client_fd, &nmethods, 1 );
			if ( n == -1 && ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ) ) return 0;
			if ( n <= 0 ) return 1;

			pair->nbytes = (size_t) nmethods;
			if ( pair->nbytes == 0 ) {
				/* No authentication methods, eh? => Nothing we can do. */
				pair->state = 2;
			}
		}

		if ( pair->state == 1 ) {
			while( pair->nbytes > 0 ) {
				char method;
				ssize_t n = read( pair->client_fd, &method, 1 );
				if ( n == -1 && ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ) ) return 0;
				if ( n <= 0 ) return 1;

				pair->nbytes--;
				if ( method == 0 ) {
					pair->hasNoAuth = 1;
				}
			}

			pair->state = 2;
		}
	}

	/* state 2: first reply (selected authentication method) */
	if ( pair->state == 2 && ( pair->client_flags & POLLOUT ) ) {
		char setMethod[2];
		setMethod[0] = pair->vers;
		setMethod[1] = pair->hasNoAuth ? 0 : 255;

		while( pair->nbytes < 2 ) {
			ssize_t n = write( pair->client_fd + pair->nbytes, setMethod, 2 - pair->nbytes );
			if ( n == -1 && ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ) ) return 0;
			if ( n <= 0 ) return 1;

			pair->nbytes += n;
		}

		if ( pair->hasNoAuth ) {
			/* Move forward */
			pair->nbytes = 0;
			pair->state = 3;
		} else {
			/* Finish here */
			return 1;
		}
	}

	/* state 3: client command and address */
	if ( pair->state == 3 && ( pair->client_flags & POLLIN ) ) {
		while ( pair->nbytes < 1 ) {
			ssize_t n = read( pair->client_fd, &pair->vers, 1 );
			if ( n == -1 && ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ) ) return 0;
			if ( n <= 0 ) return 1;

			pair->nbytes += n;
			if ( pair->vers != 5 ) {
				fprintf( stderr, "protocol version not recognised (again ?!?): %d\n", (int)pair->vers );
				return 1;
			}
		}

		while ( pair->nbytes < 2 ) {
			ssize_t n = read( pair->client_fd, &( pair->cmd ), 1 );
			if ( n == -1 && ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ) ) return 0;
			if ( n <= 0 ) return 1;

			pair->nbytes += n;
			if ( pair->cmd != 1 ) {
				pair->error = 2; /* We only accept BIND commands */
			}
		}

		while ( pair->nbytes < 3 ) {
			char resv;
			ssize_t n = read( pair->client_fd, &resv, 1 );
			if ( n == -1 && ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ) ) return 0;
			if ( n <= 0 ) return 1;

			pair->nbytes += n;
			if ( resv != 0 ) {
				pair->error = 1; /* This byte must be zero per RFC */
			}
		}

		while ( pair->nbytes < 4 ) {
			ssize_t n = read( pair->client_fd, &pair->serverToAddr.type, 1 );
			if ( n == -1 && ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ) ) return 0;
			if ( n <= 0 ) return 1;

			pair->nbytes += n;
		}

		switch ( pair->serverToAddr.type ) {
		case 1: /* IPv4 */
			pair->serverToAddr.addr_len = sizeof( pair->serverToAddr.addr.in4_addr );
			pair->serverToAddr.addr.in4_addr.sin_family = AF_INET;

			while( pair->nbytes < 8 ) {
				ssize_t n = read( pair->client_fd, (void*)( &pair->serverToAddr.addr.in4_addr.sin_addr ) + ( pair->nbytes - 4 ), 8 - pair->nbytes );
				if ( n == -1 && ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ) ) return 0;
				if ( n <= 0 ) return 1;

				pair->nbytes += n;
			}
			while ( pair->nbytes < 10 ) {
				ssize_t n = read( pair->client_fd, (void*)( &pair->serverToAddr.addr.in4_addr.sin_port ) + ( pair->nbytes - 8 ), 10 - pair->nbytes );
				if ( n == -1 && ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ) ) return 0;
				if ( n <= 0 ) return 1;

				pair->nbytes += n;
			}

			pair->nbytes = 0;
			pair->state = ( pair->error == 0 ) ? 4 : 6;
			break;

		case 3: /* Host name */
			if ( pair->nbytes == 4 ) {
				/* For host name, we now need the length of the address */
				pair->serverToAddr.addr_len = sizeof( pair->serverToAddr.addr.dns_addr );
				memset( pair->serverToAddr.addr.dns_addr.host, '\0', sizeof( pair->serverToAddr.addr.dns_addr.host ) );

				ssize_t n = read( pair->client_fd, &( pair->serverToAddr.addr.dns_addr.hostLen ), 1 );
				if ( n == -1 && ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ) ) return 0;
				if ( n <= 0 ) return 1;

				pair->nbytes++;
			}

			while ( pair->nbytes < 5 + pair->serverToAddr.addr.dns_addr.hostLen ) {
				/* Host name itself */
				ssize_t n = read( pair->client_fd, (void*)( &pair->serverToAddr.addr.dns_addr.host ) + ( pair->nbytes - 5 ), 5 + pair->serverToAddr.addr.dns_addr.hostLen - pair->nbytes );
				if ( n == -1 && ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ) ) return 0;
				if ( n <= 0 ) return 1;

				pair->nbytes += n;
			}
			while ( pair->nbytes < 7 + pair->serverToAddr.addr.dns_addr.hostLen ) {
				/* Port */
				ssize_t n = read( pair->client_fd, (void*)( &pair->serverToAddr.addr.dns_addr.port ) + ( pair->nbytes - 5 - pair->serverToAddr.addr.dns_addr.hostLen ), 7 + pair->serverToAddr.addr.dns_addr.hostLen - pair->nbytes );
				if ( n == -1 && ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ) ) return 0;
				if ( n <= 0 ) return 1;

				pair->nbytes += n;
			}

			pair->nbytes = 0;
			pair->state = ( pair->error == 0 ) ? 4 : 6;
			break;

		case 4: /* IPv6 */
			while ( pair->nbytes < 20 ) {
				ssize_t n = read( pair->client_fd, (void*)( &pair->serverToAddr.addr.in6_addr.sin6_addr ) + ( pair->nbytes - 4 ), 20 - pair->nbytes );
				if ( n == -1 && ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ) ) return 0;
				if ( n <= 0 ) return 1;

				pair->nbytes += n;
			}
			while ( pair->nbytes < 22 ) {
				ssize_t n = read( pair->client_fd, (void*)( &pair->serverToAddr.addr.in6_addr.sin6_port ) + ( pair->nbytes - 20 ), 22 - pair->nbytes );
				if ( n == -1 && ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ) ) return 0;
				if ( n <= 0 ) return 1;

				pair->nbytes += n;
			}

			pair->nbytes = 0;
			pair->state = ( pair->error == 0 ) ? 4 : 6;
			break;

		default: /* Unknown */
			pair->nbytes = 0;
			pair->state = 6;
			pair->error = 1;
			break;
		}

		printf( "From " );
		print_sockaddr( &( pair->clientFromAddr ) );
		printf( " bind " );
		print_sockaddr( &( pair->serverToAddr ) );
		printf( "\n" );
	}

	/* state 4 or 5: opening of forward connection */
	if ( pair->state == 4 || pair->state == 5 ) {
		int serverSockDomain;
		int res;

		if ( pair->serverToAddr.type == 3 ) {
			if ( pair->state == 4 && pair->nbytes == 0 ) {
				pair->nbytes++;

				char portBuf[16];
				snprintf( portBuf, sizeof( portBuf ), "%d", ntohs( pair->serverToAddr.addr.dns_addr.port ) );

#ifdef ARES
				struct ares_addrinfo_hints hints;
				memset( &hints, 0, sizeof( hints ) );
				hints.ai_family = forward_af;
				hints.ai_socktype = SOCK_STREAM;
				hints.ai_flags = ARES_AI_NOSORT;

				struct handshake_ares_res* data = (struct handshake_ares_res*) malloc( sizeof( struct handshake_ares_res ) );
				if ( data == NULL ) {
					pair->nbytes = 0;
					pair->state = 6;
					pair->error = 1;
				} else {
					data->status = 0;
					data->error = 0;
					data->result = NULL;
					ares_getaddrinfo( channel, pair->serverToAddr.addr.dns_addr.host, portBuf, &hints, handshake_ares_callback, (void*)data );
					pair->res_ares = data;
				}
#else
				struct addrinfo hints;
				memset( &hints, 0, sizeof( hints ) );
				hints.ai_family = forward_af;
				hints.ai_socktype = SOCK_STREAM;

				int ret = getaddrinfo( pair->serverToAddr.addr.dns_addr.host, portBuf, &hints, &( pair->res_base ) );
				if ( ret != 0 ) {
					freeaddrinfo( pair->res_base );
					pair->res_base = NULL;
					pair->nbytes = 0;
					pair->state = 6;
					pair->error = 4;
				} else {
					pair->res_cur = pair->res_base;
					pair->state = 5;
				}
#endif
			}

#ifdef ARES
			if ( pair->state == 4 && pair->res_ares->status == 1 ) {
				if ( pair->res_ares->error != ARES_SUCCESS ) {
					pair->res_base = NULL;
					pair->res_cur = NULL;
					pair->nbytes = 0;
					pair->state = 6;
					pair->error = 4;
				} else {
					pair->res_base = pair->res_ares->result;
					pair->res_cur = pair->res_ares->result->nodes;
					pair->nbytes = 0;
					pair->state = 5;
				}

				free( pair->res_ares );
				pair->res_ares = NULL;
			}
#endif

			if ( pair->state < 5 ) {
				return 0;
			}

			if ( pair->server_fd >= 0 ) {
				if ( pair->server_flags & ( POLLERR | POLLHUP | POLLNVAL ) ) {
					close( pair->server_fd );
					pair->server_fd = -1;
				} else if ( !pair->server_flags ) {
					return 0;
				}
			}

			if ( pair->server_fd == -1 ) {
				while ( pair->res_cur != NULL ) {
					pair->server_fd = socket( pair->res_cur->ai_family, pair->res_cur->ai_socktype, pair->res_cur->ai_protocol );
					if ( pair->server_fd == -1 ) {
						pair->res_cur = pair->res_cur->ai_next;
						continue;
					}

					res = connect( pair->server_fd, pair->res_cur->ai_addr, pair->res_cur->ai_addrlen );
					if ( res == -1 ) {
						if ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS ) return 0;

						close( pair->server_fd );
						pair->server_fd = -1;
						pair->res_cur = pair->res_cur->ai_next;
						continue;
					}

					serverSockDomain = pair->res_cur->ai_family;
					break;
				}
			}

#ifdef ARES
			ares_freeaddrinfo( pair->res_base );
#else
			freeaddrinfo( pair->res_base );
#endif
			pair->res_base = NULL;
			pair->res_cur = NULL;
			pair->nbytes = 0;
			pair->state = 6;

			if ( pair->server_fd == -1 ) {
				pair->error = 1;
			}
		} else {
			pair->state = 5; /* Directly promote to state 5 */
			serverSockDomain = pair->serverToAddr.type == 1 ? PF_INET : PF_INET6;

			if ( pair->server_fd == -1 ) {
				pair->server_fd = socket( serverSockDomain, SOCK_STREAM, 0 );

				if ( pair->server_fd == -1 ) {
					res = -1;
					pair->error = 1;
				} else {
					res = connect( pair->server_fd, (struct sockaddr *)&pair->serverToAddr.addr, pair->serverToAddr.addr_len );

					if ( res == 0 ) {
						/* Good */
						pair->state = 6;
					} else {
						if ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS ) return 0;

						res = -1;
						pair->error = 1;
						close( pair->server_fd );
						pair->server_fd = -1;
					}
				}
			} else if ( pair->server_flags & ( POLLIN | POLLOUT ) ) {
				/* Connection opened async */
				pair->state = 6;
				pair->nbytes = 0;
			} else if ( pair->server_flags ) {
				/* Connection failed */
				pair->state = 6;
				pair->nbytes = 0;
				pair->error = 1;

				if ( pair->server_flags & POLLERR ) {
					int errval;
					socklen_t errlen = sizeof( errval );

					int ret = getsockopt( pair->server_fd, SOL_SOCKET, SO_ERROR, &errval, &errlen );
					if ( ret >= 0 ) {
						errno = errval;
						res = -1;
					}
				}
				close( pair->server_fd );
				pair->server_fd = -1;
			}
		}

		if ( pair->state == 6 ) {
			if ( pair->server_fd == -1 ) {
				if ( res == -1 && pair->error == 1 ) {
					switch ( res ) {
					case ENETUNREACH:
						pair->error = 3;
						break;
					case EHOSTUNREACH:
						pair->error = 4;
						break;
					case ECONNREFUSED:
						pair->error = 5;
						break;
					case EAFNOSUPPORT:
						pair->error = 8;
						break;
					}
				}
			} else {
				pair->serverFromAddr.type = serverSockDomain == PF_INET6 ? 4 : 1;
				socklen_t memSpace = sizeof( pair->serverFromAddr.addr );
				getsockname( pair->server_fd, (struct sockaddr *)&pair->serverFromAddr.addr, &memSpace );
				//setsockopt( pair->server_fd, SOL_SOCKET, SO_NOSIGPIPE, &optOne, sizeof( optOne ) );
			}
		}
	}

	/* state 6: server to client response */
	if ( pair->state == 6 && ( pair->client_flags & POLLOUT ) ) {
		size_t connRespLen = 4 + ( pair->serverFromAddr.type == 4 ? 18 : 6 );

		while ( pair->nbytes < connRespLen ) {
			char* connResp = malloc( connRespLen );
			connResp[0] = pair->vers;
			connResp[1] = pair->error;
			connResp[2] = '\0';
			connResp[3] = pair->serverFromAddr.type;

			if ( pair->serverFromAddr.type == 4 ) {
				memcpy( connResp + 4, &pair->serverFromAddr.addr.in6_addr.sin6_addr, 16 );
				memcpy( connResp + 20, &pair->serverFromAddr.addr.in6_addr.sin6_port, 2 );
			} else {
				memcpy( connResp + 4, &pair->serverFromAddr.addr.in4_addr.sin_addr, 4 );
				memcpy( connResp + 8, &pair->serverFromAddr.addr.in4_addr.sin_port, 2 );
			}

			ssize_t n = write( pair->client_fd, connResp + pair->nbytes, connRespLen - pair->nbytes );
			free( connResp );

			if ( n == -1 && ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ) ) return 0;
			if ( n <= 0 ) return 1;
			pair->nbytes += n;
		}

		if ( pair->server_fd == -1 ) {
			return 1;
		}

		/* And the handshake is finished. Let's get back to business */
		pair->state = 0;
		pair->client_dirs = 0x3;
		pair->server_dirs = 0x3;
	}

	return 0;
}

/**
 * Compute the events to watch for in poll() for a pair in SOCKS handshake mode.
 */
void handshake_flags( struct socks_connection_pair* pair, short int* client_flags, short int* server_flags ) {
	( *client_flags ) = 0;
	( *server_flags ) = 0;

	if ( pair->state == 1 || pair->state == 3 ) {
		( *client_flags ) |= POLLIN;
	}
	if ( pair->state == 2 || pair->state == 6 ) {
		( *client_flags ) |= POLLOUT;
	}
	/* state 4 is DNS query, which is handled by the underlying library. */
	if ( pair->state == 5 ) {
		( *server_flags ) |= POLLOUT;
	}
}

/**
 * Forwarding mode
 * ---------------
 */

/**
 * Wrapper around recv() with proper error detection
 *
 * This handles asynchronous sockets. Returns 0 on success, 1 for EOF, and 2 for error.
 */
int handle_recv( int fd, char* buf, size_t* len ) {
	ssize_t n = recv( fd, buf + ( *len ), 16384 - ( *len ), 0 );
	if ( n == -1 ) {
		if ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ) return 0;
		return 2;
	} else if ( n == 0 ) {
		return 1;
	} else {
		( *len ) += n;
		return 0;
	}
}

/**
 * Wrapper around write() with proper error detection
 *
 * This handles asynchronous sockets. Returns 0 on success, 1 for EOF, and 2 for error.
 */
int handle_send( int fd, char* buf, size_t* len ) {
	if ( ( *len ) == 0 ) {
		return 0;
	}
	ssize_t n = write( fd, buf, ( *len ) );
	if ( n == -1 ) {
		if ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ) return 0;
		if ( errno == EPIPE ) return 1;
		return 2;
	} else {
		if ( n == ( *len ) ) {
			( *len ) = 0;
		} else {
			memmove( buf, buf + n, ( *len ) - n );
			( *len ) -= n;
		}
		return 0;
	}
}

/**
 * Perform work for a pair in forward mode
 */
int forward_handle( struct socks_connection_pair* pair ) {
	if ( pair->client_flags &  ( POLLERR | POLLNVAL ) || pair->server_flags & ( POLLERR | POLLNVAL ) ) {
		return 1;
	}

	if ( pair->client_dirs & 0x2 && pair->client_flags & POLLOUT ) {
		int res = handle_send( pair->client_fd, pair->stc_buf, &( pair->stc_len ) );
		if ( res > 0 ) {
			close( pair->client_fd );
			pair->client_fd = -1;
			pair->client_dirs = 0;

			if ( pair->server_dirs & 0x1 ) {
				pair->server_dirs &= ~0x1;
				shutdown( pair->server_fd, SHUT_RD );
			}
		}
	}

	if ( pair->server_dirs & 0x2 && pair->server_flags & POLLOUT ) {
		int res = handle_send( pair->server_fd, pair->cts_buf, &( pair->cts_len ) );
		if ( res > 0 ) {
			close( pair->server_fd );
			pair->server_fd = -1;
			pair->server_dirs = 0;

			/* We cannot receive anything anymore from the other side */
			if ( pair->client_dirs & 0x1 ) {
				pair->client_dirs &= ~0x1;
				shutdown( pair->client_fd, SHUT_RD );
			}
		}
	}

	if ( pair->client_dirs & 0x1 && pair->client_flags & POLLIN ) {
		int res = handle_recv( pair->client_fd, pair->cts_buf, &( pair->cts_len ) );
		if ( res > 0 ) {
			close( pair->client_fd );
			pair->client_fd = -1;
			pair->client_dirs = 0;

			if ( pair->server_dirs & 0x1 ) {
				pair->server_dirs &= ~0x1;
				shutdown( pair->server_fd, SHUT_RD );
			}
		}
	}

	if ( pair->server_dirs & 0x1 && pair->server_flags & POLLIN ) {
		int res = handle_recv( pair->server_fd, pair->stc_buf, &( pair->stc_len ) );
		if ( res > 0 ) {
			close( pair->server_fd );
			pair->server_fd = -1;
			pair->server_dirs = 0;

			/* We cannot receive anything anymore from the other side */
			if ( pair->client_dirs & 0x1 ) {
				pair->client_dirs &= ~0x1;
				shutdown( pair->client_fd, SHUT_RD );
			}
		}
	}

	if ( pair->server_fd == -1 && pair->stc_len == 0 ) {
		close( pair->client_fd );
		pair->client_fd = -1;
		pair->client_dirs = 0;
	}

	if ( pair->client_fd == -1 && pair->cts_len == 0 ) {
		close( pair->server_fd );
		pair->server_fd = -1;
		pair->server_dirs = 0;
	}

	return pair->client_fd == -1 && pair->server_fd == -1;
}

/**
 * Compute the events to watch for in poll() for a pair in forward mode.
 */
void foward_flags( struct socks_connection_pair* pair, short int* client_flags, short int* server_flags ) {
	( *client_flags ) = 0;
	if ( pair->cts_len < 16384 && pair->client_dirs & 0x1 ) ( *client_flags ) |= POLLIN;
	if ( pair->stc_len > 0     && pair->client_dirs & 0x2 ) ( *client_flags ) |= POLLOUT;

	( *server_flags ) = 0;
	if ( pair->stc_len < 16384 && pair->server_dirs & 0x1 ) ( *server_flags ) |= POLLIN;
	if ( pair->cts_len > 0     && pair->server_dirs & 0x2 ) ( *server_flags ) |= POLLOUT;
}

/**
 * Main code
 * ---------
 */

/**
 * Program entry point
 */
int main( int argc, char** argv ) {
	int help = 0;
	int version = 0;
#ifdef ARES
	char* dns_servers = NULL;
#define DNSOPT "d:"
#else
#define DNSOPT
#endif

	static struct option long_options[] = {
		{ "help", 0, NULL, 'h' },
		{ "version", 0, NULL, 'v' },
#ifdef ARES
		{ "dns-servers", 1, NULL, 'd' },
#endif
		{ 0, 0, NULL, 0 }
	};

	while ( 1 ) {
		int opt = getopt_long( argc, argv, "hv46" DNSOPT, long_options, NULL );
		if ( opt < 0 ) break;
		if ( opt == '?' ) exit( 2 );
		if ( opt == 'h' ) help++;
		if ( opt == 'v' ) version++;
		if ( opt == '4' ) forward_af = AF_INET;
		if ( opt == '6' ) forward_af = AF_INET6;
#ifdef ARES
		if ( opt == 'd' ) dns_servers = strdup( optarg );
#endif
	}

	if ( version ) {
#ifdef PACKAGE_STRING
		fputs( PACKAGE_STRING "\n", stderr );
#endif
#ifdef PACKAGE_URL
		fputs( PACKAGE_URL "\n", stderr );
#endif
		fputs( "\n", stderr );
		fputs( "Copyright 2023 Alexandre Emsenhuber\n", stderr );
		fputs( "Licensed under the Apache License, Version 2.0\n", stderr );

		exit( EXIT_SUCCESS );
	}

	if ( help || ( argc - optind != 1 && argc - optind != 2 ) ) {
		fprintf( stderr, "Usage: %s [OPTION...] [--] [<host>] <port>\n", argv[0] );

		if ( help ) {
			fputs( "\n", stderr );
			fputs( "Program options:\n", stderr );
			fputs( "  -h --help              Display this help message and exit\n", stderr );
			fputs( "  -v --version           Display version information and exit\n", stderr );
			fputs( "  -4                     Only allow forward connections to IPv4 addresses\n", stderr );
			fputs( "  -6                     Only allow forward connections to IPv6 addresses\n", stderr );
			fputs( "  -d --dns-servers=LIST  Comma-separated list of DNS servers (and ports) to use instead of resolv.conf\n", stderr );
			exit( EXIT_SUCCESS );
		} else {
			exit( 2 );
		}
	}

#ifdef ARES
	int ares = ares_library_init( ARES_LIB_INIT_ALL );
	if ( ares != 0 ) {
		fprintf( stderr, "ares initialization failure: %s\n", ares_strerror( ares ) );
		exit( EXIT_FAILURE );
	}

	ares = ares_init( &channel );
	if ( ares != ARES_SUCCESS ) {
		fprintf( stderr, "ares initialization failure: %s\n", ares_strerror( ares ) );
		exit( EXIT_FAILURE );
	}

	if ( dns_servers != NULL ) {
		ares = ares_set_servers_ports_csv( channel, dns_servers );
		if ( ares != ARES_SUCCESS ) {
			fprintf( stderr, "failure setting DNS servers: %s\n", ares_strerror( ares ) );
			exit( EXIT_FAILURE );
		}

		free( dns_servers );
		dns_servers = NULL;
	}
#endif

	char* server_addr = NULL;
	char* server_port = NULL;

	if ( argc - optind == 1 ) {
		server_port = argv[ optind + 0 ];
	} else if ( argc - optind == 2 ) {
		server_addr = argv[ optind + 0 ];
		server_port = argv[ optind + 1 ];
	} else {
		fprintf( stderr, "Usage: %s [host] port\n", argv[ 0 ] );
		exit( 2 );
	}

	signal(	SIGPIPE, SIG_IGN );

	int listen_fd = -1;
	int server_family = 0;

	struct addrinfo hints;
	memset( &hints, '\0', sizeof( hints ) );
	hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG | AI_PASSIVE;   /* Allow server mode */

	struct addrinfo* res;
	int ret = getaddrinfo( server_addr, server_port, &hints, &res );
	if ( ret != 0 ) {
		fprintf( stderr, "getaddrinfo: %s\n", gai_strerror( ret ) );
		exit( EXIT_FAILURE );
	}

	struct addrinfo* item;
	for ( item = res; item != NULL; item = item->ai_next ) {
		listen_fd = socket( item->ai_family, item->ai_socktype, item->ai_protocol );
		if ( listen_fd == -1 ) continue;

		int bool_true = 1;
		setsockopt( listen_fd, SOL_SOCKET, SO_REUSEADDR, &bool_true, sizeof( bool_true ) );

		int ret = bind( listen_fd, item->ai_addr, item->ai_addrlen );
		if ( ret == -1 ) {
			close( listen_fd );
			listen_fd = -1;
			continue;
		}

		ret = listen( listen_fd, SOMAXCONN );
		if ( ret == -1 ) {
			close( listen_fd );
			listen_fd = -1;
			continue;
		}

		/* Actually, we are now good */
		server_family = item->ai_family;
		break;
	}

	if ( listen_fd == -1 ) {
		perror( "Could not create server" );
		exit( EXIT_FAILURE );
	}

	freeaddrinfo( res );

	struct socks_connection_pair* list = NULL;
	size_t connections_alloc = 0;
	size_t connections_open = 0;

	/* The mail loop */
	/* ------------- */
	while ( 1 ) {
		/* poll() preparation */
		size_t nfds = 2 * connections_open + 1;
		int timeout = -1;

#ifdef ARES
		fd_set readfds, writefds;
		FD_ZERO( &readfds );
		FD_ZERO( &writefds );
		int sfds = ares_fds( channel, &readfds, &writefds );
		size_t afds = 0;
		if ( sfds > 0 ) {
			for ( int fd = 0; fd < sfds; fd++ ) {
				if ( FD_ISSET( fd, &readfds ) || FD_ISSET( fd, &writefds ) ) afds++;
			}
		}
		nfds += afds;
#endif

		struct pollfd* fds = malloc( sizeof( struct pollfd ) * nfds );

		if ( fds == NULL ) {
			perror( "malloc" );
			exit( EXIT_FAILURE );
		}

		fds[0].fd = listen_fd;
		fds[0].events = POLLIN;
		fds[0].revents = 0;

		for ( size_t i = 0; i < connections_open; i++ ) {
			fds[2*i+1].fd = list[i].client_fd;
			fds[2*i+2].fd = list[i].server_fd;

			if ( list[i].state == 0 ) {
				foward_flags( &( list[i] ), &( fds[2*i+1].events ), &( fds[2*i+2].events ) );
			} else if ( list[i].state > 0 ) {
				handshake_flags( &( list[i] ), &( fds[2*i+1].events ), &( fds[2*i+2].events ) );
			}

			fds[2*i+1].revents = 0;
			fds[2*i+2].revents = 0;
		}

#ifdef ARES
		size_t ifds = 2 * connections_open + 1;
		for ( int fd = 0; fd < sfds; fd++ ) {
			if ( FD_ISSET( fd, &readfds ) || FD_ISSET( fd, &writefds ) ) {
				fds[ifds].fd = fd;
				fds[ifds].events = 0;
				if ( FD_ISSET( fd, &readfds ) ) fds[ifds].events |= POLLIN;
				if ( FD_ISSET( fd, &writefds ) ) fds[ifds].events |= POLLOUT;
				fds[ifds].revents = 0;
				ifds++;
			}
		}
#endif

		/* Actual poll() call */
		int nsel = poll( fds, nfds, timeout );
		if ( nsel == -1 ) {
			perror( "poll" );
			continue;
		}

		/* Parsing of poll() result */
		short listen_flags = fds[0].revents;

		for ( size_t i = 0; i < connections_open; i++ ) {
			list[i].client_flags = fds[2*i+1].revents;
			list[i].server_flags = fds[2*i+2].revents;
		}

#ifdef ARES
		FD_ZERO( &readfds );
		FD_ZERO( &writefds );

		for ( size_t i = 0; i < afds; i++ ) {
			size_t ifds = 2 * connections_open + 1 + i;
			if ( fds[ifds].revents & POLLIN ) FD_SET( fds[ifds].fd, &readfds );
			if ( fds[ifds].revents & POLLOUT ) FD_SET( fds[ifds].fd, &writefds );
		}

		ares_process( channel, &readfds, &writefds );
#endif

		free( fds );
		fds = NULL;

		/* New connection */
		if ( listen_flags & POLLIN ) {
			struct socks_connection_pair new_pair;
			socks_accept( listen_fd, server_family, &new_pair );

			if ( new_pair.state > 0 ) {
				if ( connections_alloc == connections_open ) {
					struct socks_connection_pair* new = realloc( list, sizeof( struct socks_connection_pair ) * ( connections_alloc + 1 ) );
					if ( new != NULL ) {
						list = new;
						connections_alloc++;
					}
				}

				if ( connections_alloc > connections_open ) {
					memcpy( list + connections_open, &new_pair, sizeof( struct socks_connection_pair ) );
					connections_open++;
				} else {
					if ( new_pair.client_fd >= 0 ) close( new_pair.client_fd );
					if ( new_pair.server_fd >= 0 ) close( new_pair.server_fd );
				}
			}
		}

		/* Existing connections */
		size_t idx = 0;
		while ( idx < connections_open ) {
			struct socks_connection_pair* itr = list + idx;
			int toClose = 0;

			if ( itr->state == 0 ) {
				toClose = forward_handle( itr );
			} else if ( itr->state > 0 ) {
				toClose = handshake_handle( itr );
			} else {
				toClose = 1;
			}

			if ( toClose ) {
#ifdef ARES
				if ( itr->res_ares != NULL ) {
					itr->res_ares->status = -1;
				}
#endif
				if ( itr->client_fd >= 0 ) close( itr->client_fd );
				if ( itr->server_fd >= 0 ) close( itr->server_fd );
				memmove( list + idx, list + idx + 1, sizeof( struct socks_connection_pair ) * ( connections_open - idx - 1 ) );
				connections_open--;
			} else {
				idx++;
			}
		}
	}
}
