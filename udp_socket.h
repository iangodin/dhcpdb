//
// Copyright (c) 2013 Ian Godin
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

#pragma once

#include <stdint.h>
#include <stdint.h>

#include <string>

struct packet;

typedef union
{
	uint32_t addr;
	uint8_t bytes[4];
} IPAddr;

////////////////////////////////////////

// Lookup name
uint32_t dns_lookup( const char *name );
std::string ip_lookup( uint32_t ip, bool numeric = true, bool fqdn = true );

////////////////////////////////////////

class udp_socket
{
public:
	// Open a socket and bind it to the addr/port (for a server).
	udp_socket( uint32_t addr, uint64_t port );

	// Open a socket to the given address (for a client).
	udp_socket( uint32_t addr );

	~udp_socket( void );

	// Receive a packet from the socket.
	// Blocks until a packet arrives.
	void recv( packet *p );

	// Send a packet to 'dest'.
	void send( uint32_t dest, packet *p );

	int fd( void ) const { return _fd; }

private:
	int _fd;
};

////////////////////////////////////////

