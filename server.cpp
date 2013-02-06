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

#include "packet.h"
#include "udp_socket.h"
#include "error.h"
#include "handler.h"
#include "daemon.h"
#include "packet_queue.h"
#include "config.h"

#include <stdio.h>
#include <syslog.h>
#include <pthread.h>
#include <getopt.h>
#include <string.h>
#include <arpa/inet.h>

#include <thread>
#include <vector>

#define NUM_THREADS 5

////////////////////////////////////////

int server( void )
{
	try
	{
		bool foreground = false;
		{
			std::string fore = configuration["foreground"] ;
			foreground = ( fore == "yes" || fore == "true" || fore == "on" );
		}

		openlog( "dhcpdb", LOG_PERROR | LOG_PID, LOG_DAEMON );

		uint32_t server_address = dns_lookup( configuration["server"].c_str() );
		if ( server_address == 0 )
			error( "No server address specified" );

		daemonize( "dhcpdb", foreground );

		syslog( LOG_INFO, "DHCP server started using address %s", ip_lookup( server_address ).c_str() );

		udp_socket s( INADDR_ANY, 67 );

		std::vector<std::thread> threads;

		packet_queue queue;
		for ( size_t t = 0; t < NUM_THREADS; ++t )
			threads.push_back( std::thread( std::bind( &handler, server_address, std::ref( s ), std::ref( queue ) ) ) );

		while ( 1 )
		{
			try
			{
				packet *p = queue.alloc();
				s.recv( p );
				queue.queue( p );
			}
			catch ( ... )
			{
			}
		}

		for ( size_t t = 0; t < threads.size(); ++t )
			queue.queue( NULL );

		for ( size_t t = 0; t < threads.size(); ++t )
			threads[t].join();
	}
	catch ( ... )
	{
		syslog( LOG_ERR, "FATAL ERROR (exiting)" );
		return -1;
	}

	return 0;
}

////////////////////////////////////////

