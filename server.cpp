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
#include "guard.h"

#include <stdio.h>
#include <syslog.h>
#include <pthread.h>
#include <getopt.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <ifaddrs.h>

#include <thread>
#include <vector>

#define NUM_THREADS 5

////////////////////////////////////////

namespace
{

void serve( uint32_t listen_address, uint32_t server_address )
{
	syslog( LOG_INFO, "DHCP server started on %s", ip_lookup( listen_address ).c_str() );

	packet_queue queue;
	std::vector<std::thread> threads;
	for ( size_t t = 0; t < NUM_THREADS; ++t )
		threads.push_back( std::thread( std::bind( &handler, server_address, std::ref( queue ) ) ) );

	udp_socket s( listen_address, 67, false );

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

}

////////////////////////////////////////

int server( const std::string &pidf )
{
	try
	{
		bool foreground = false;
		{
			std::string fore = configuration["foreground"] ;
			foreground = ( fore == "yes" || fore == "true" || fore == "on" );
		}

		openlog( "dhcpdb", LOG_PERROR | LOG_PID, LOG_DAEMON );

		daemonize( "dhcpdb", foreground );

		if ( !pidf.empty() )
			pidfile( pidf );

		std::vector<std::thread> threads;

		uint32_t main_ip = INADDR_ANY;
		if ( configuration.find( "server" ) != configuration.end() )
		{
			main_ip = dns_lookup( configuration["server"].c_str() );
			threads.push_back( std::thread( std::bind( &serve, main_ip, main_ip ) ) );
		}
		else
		{
			struct ifaddrs *addrs;
			if ( getifaddrs( &addrs ) != 0 )
				error( errno, "Getting network interfaces" );
			auto g = make_guard( [=](){ freeifaddrs( addrs ); } );

			struct ifaddrs *ifa = addrs;
			while ( ifa )
			{
				sockaddr_in *addr = reinterpret_cast<sockaddr_in*>( ifa->ifa_addr );
				if ( addr != NULL && addr->sin_family == AF_INET )
				{
					uint32_t ip = addr->sin_addr.s_addr;
					if ( main_ip == INADDR_ANY || main_ip == htonl( INADDR_LOOPBACK ) || main_ip == INADDR_BROADCAST )
						main_ip = ip;
					threads.push_back( std::thread( std::bind( &serve, ip, ip ) ) );
				}
				ifa = ifa->ifa_next;
			}
		}
		threads.push_back( std::thread( std::bind( &serve, INADDR_ANY, main_ip ) ) );

		for ( size_t i = 0; i < threads.size(); ++i )
			threads[i].join();
	}
	catch ( ... )
	{
		syslog( LOG_ERR, "FATAL ERROR (exiting)" );
		return -1;
	}

	return 0;
}

////////////////////////////////////////

