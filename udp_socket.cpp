
#include "udp_socket.h"
#include "guard.h"
#include "error.h"
#include "packet.h"
#include "format.h"
#include "lookup.h"

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <exception>

////////////////////////////////////////

udp_socket::udp_socket( uint32_t addr, uint64_t port, bool broadcast )
{
	// Create the socket
	_fd = ::socket( PF_INET, SOCK_DGRAM, IPPROTO_UDP );
	if ( _fd < 0 )
		error( errno, "Error creating server socket" );

	// Close if we exit prematurely
	auto guard = make_guard( [&]() { ::close( _fd ); _fd = -1; } );

	// Set the socket to be reusable immediately after closing
	if ( port > 0 )
	{
		int opt = 1;
		if ( setsockopt( _fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt) ) != 0 )
			error( errno, "Error reusing address" );
	}

	if ( broadcast )
	{
		int opt = 1;
		// Turn on broadcasting
		if ( setsockopt( _fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt) ) != 0 )
			error( errno, "Could not set broadcast" );
	}

	// Bind the socket
	if( port != 0 )
	{
		struct sockaddr_in servaddr;
		size_t servsize = sizeof(servaddr);
		memset( (void *)(&servaddr), 0, servsize );
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = addr;
		servaddr.sin_port = htons( port );

		if ( ::bind( _fd, (struct sockaddr *)&servaddr, servsize ) != 0 )
			error( errno, format( "Error binding socket ({0})", ip_lookup( addr ) ) );
	}

	guard.commit();
}

////////////////////////////////////////

udp_socket::~udp_socket( void )
{
	::close( _fd );
}

////////////////////////////////////////

void udp_socket::recv( packet *p )
{
	if ( recvfrom( _fd, p, sizeof(packet), 0, NULL, NULL ) < 0 )
		error( errno, "Error recvfrom" );
}

////////////////////////////////////////

void udp_socket::send( uint32_t dest, uint16_t port, packet *p )
{
	struct sockaddr_in recipient;
	memset( (void *)(&recipient), 0, sizeof(recipient) );
	recipient.sin_family = AF_INET;
	recipient.sin_addr.s_addr = dest;
	recipient.sin_port = htons( port );

	uint8_t *start = reinterpret_cast<uint8_t*>( p );
	uint8_t *end = start + sizeof(packet)-1;
	while ( *end == '\0' )
		end--;

	size_t size = end - start + 1;

	ssize_t sent = ::sendto( _fd, p, size, 0, (struct sockaddr *)&recipient, sizeof(recipient) );
	if ( sent != size )
		error( errno, "Error sendto" );
}

////////////////////////////////////////

