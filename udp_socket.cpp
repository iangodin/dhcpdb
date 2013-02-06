
#include "udp_socket.h"
#include "guard.h"
#include "error.h"
#include "packet.h"
#include "format.h"

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

uint32_t dns_lookup( const char *name )
{
	uint32_t ret = 0;

	// Try a numeric address first.
	if ( inet_pton( AF_INET, name, &ret ) == 1 )
		return ret;

	struct addrinfo *res0 = NULL;
	int err = EAI_AGAIN;
	struct addrinfo hints;

	memset( &hints, 0, sizeof(hints) );
	hints.ai_family = AF_INET;

	while ( err == EAI_AGAIN )
		err = getaddrinfo( name, NULL, &hints, &res0 );

	if ( err == 0 )
	{
		struct addrinfo *res = res0;
		for ( ; res; res=res->ai_next )
		{
			if ( res->ai_addrlen == sizeof(struct sockaddr_in) )
				break;
		}

		if ( res )
		{
			struct sockaddr_in *a = (struct sockaddr_in *)( res->ai_addr );
			ret = a->sin_addr.s_addr;
		}

		freeaddrinfo( res0 );

		if ( !res )
			error( std::string( "Name lookup failed " ) + name );
	}
	else
		error( std::string( "Name lookup failed " ) + name );

	if ( ret == 0 )
		error( std::string( "Name lookup failed " ) + name );

	return ret;
}

////////////////////////////////////////

std::string ip_lookup( uint32_t ip, bool numeric )
{
	char node[NI_MAXHOST];

	struct sockaddr_in sa;
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = ip;

	int err = EAI_AGAIN;
	while ( err == EAI_AGAIN )
		err = getnameinfo( (struct sockaddr*)&sa, sizeof(sa), node, sizeof(node), NULL, 0, NI_NAMEREQD );

	if ( err != 0 )
	{
		// Try a numeric address...
		if ( !numeric || ( inet_ntop( AF_INET, &ip, node, sizeof(node) ) == NULL ) )
			error( std::string( "IP lookup failed: " ) + gai_strerror( err ) );
	}

	return std::string( node );
}

////////////////////////////////////////

udp_socket::udp_socket( uint32_t addr, uint64_t port )
{
	// Create the socket
	_fd = ::socket( AF_INET, SOCK_DGRAM, 0 );
	if ( _fd < 0 )
		error( errno, "Error creating server socket" );

	// Close if we exit prematurely
	auto guard = make_guard( [&]() { ::close( _fd ); _fd = -1; } );

	// Set the socket to be reusable immediately after closing
	int opt = 1;
	if ( setsockopt( _fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt) ) != 0 )
		error( errno, "Error reusing address" );

	// Bind the socket
	struct sockaddr_in servaddr;
	size_t servsize = sizeof(servaddr);
	memset( (void *)(&servaddr), 0, servsize );
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = addr;
	servaddr.sin_port = htons( port );

	if ( ::bind( _fd, (struct sockaddr *)&servaddr, servsize ) != 0 )
		error( errno, format( "Error binding socket ({0})", ip_lookup( addr ) ) );

	guard.commit();
}

////////////////////////////////////////

udp_socket::udp_socket( uint32_t addr )
{
	_fd = ::socket( AF_INET, SOCK_DGRAM, 0 );
	if ( _fd < 0 )
		error( errno, "Error creating client socket" );

	// Close if we exit prematurely
	auto guard = make_guard( [&]() { ::close( _fd ); _fd = -1; } );

	// Set the socket to be reusable immediately after closing
	int opt = 1;
	if ( setsockopt( _fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt) ) != 0 )
		error( errno, "Error reusing address" );

	// Turn on broadcasting
	if ( setsockopt( _fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt) ) != 0 )
		error( errno, "Could not set broadcast" );

	// Bind the socket
	struct sockaddr_in servaddr;
	size_t servsize = sizeof(servaddr);
	memset( (void *)(&servaddr), 0, servsize );
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = addr;
	servaddr.sin_port = htons( 67 );
	if ( ::bind( _fd, (struct sockaddr *)&servaddr, servsize ) != 0 )
		error( errno, "Error binding socket" );

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

void udp_socket::send( uint32_t dest, packet *p )
{
	struct sockaddr_in recipient;
	memset( (void *)(&recipient), 0, sizeof(recipient) );
	recipient.sin_family = AF_INET;
	recipient.sin_addr.s_addr = htonl( dest );
	recipient.sin_port = htons( 68 );

	uint8_t *start = reinterpret_cast<uint8_t*>( p );
	uint8_t *end = start + sizeof(packet)-1;
	while ( *end == '\0' )
		end--;

	size_t size = end - start + 1;
	std::cout << "Sending: " << size << std::endl;

	ssize_t sent = ::sendto( _fd, p, size, 0, (struct sockaddr *)&recipient, sizeof(recipient) );
	if ( sent != size )
		error( errno, "Error sendto" );
}

////////////////////////////////////////

