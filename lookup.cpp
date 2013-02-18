//
// Copyright (c) 2012 Ian Godin
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#include "lookup.h"
#include "error.h"

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

std::string ip_lookup( uint32_t ip, bool numeric, bool fqdn )
{
	if ( ip == 0 )
		return "0.0.0.0";

	if ( ip == INADDR_BROADCAST )
		return "255.255.255.255";

	char node[NI_MAXHOST];

	struct sockaddr_in sa;
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = ip;

	int err = EAI_AGAIN;
	int flags = 0;
	if ( !numeric )
		flags |= NI_NAMEREQD;
	if ( !fqdn )
		flags |= NI_NOFQDN;
	while ( err == EAI_AGAIN )
		err = getnameinfo( (struct sockaddr*)&sa, sizeof(sa), node, sizeof(node), NULL, 0, NI_NOFQDN );

	if ( err != 0 )
	{
		// Try a numeric address...
		if ( !numeric || ( inet_ntop( AF_INET, &ip, node, sizeof(node) ) == NULL ) )
			error( std::string( "IP lookup failed: " ) + gai_strerror( err ) );
	}

	return std::string( node );
}

////////////////////////////////////////

std::string ip_string( uint32_t ip )
{
	char node[NI_MAXHOST];
	if ( inet_ntop( AF_INET, &ip, node, sizeof(node) ) == NULL )
		error( std::string( "IP lookup failed: " ) + strerror( errno ) );
	return std::string( node );
}

////////////////////////////////////////

