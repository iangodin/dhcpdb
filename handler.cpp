
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include <algorithm>
#include <set>

#include "lookup.h"
#include "udp_socket.h"
#include "packet.h"
#include "packet_queue.h"
#include "error.h"
#include "backend.h"
#include "format.h"
#include "option.h"
#include "config.h"

std::mutex printmutex;

////////////////////////////////////////

void extractOptions( packet *p, std::vector<std::string> &opts )
{
	const uint8_t *options = p->options;
	const uint8_t *end = p->options + 312;
	if ( options[0] == 0x63 && options[1] == 0x82 && options[2] == 0x53 && options[3] == 0x63 )
	{
		options += 4; // Skip cookie

		while( *options != DOP_END_OPTION && options < end )
		{
			if ( options[0] != 0 )
			{
				size_t n = options[1];
				opts.push_back( std::string( reinterpret_cast<const char *>( options ), n + 2 ) );
				options += ( 2 + options[1] );
			}
			else
				options++;
		}
	}
}

////////////////////////////////////////

void fillOptions( packet *p, const std::vector<std::string> &opts )
{
	uint8_t *options = p->options;
	*options++ = 0x63;
	*options++ = 0x82;
	*options++ = 0x53;
	*options++ = 0x63;

	for ( auto &o: opts )
	{
		if( o.empty() )
			continue;

		if ( o[0] == DOP_TFTP_SERVERNAME )
		{
			p->siaddr = dns_lookup( &o[2] );
			continue;
		}

		if ( o[0] == DOP_BOOT_FILENAME )
		{
			size_t n = uint8_t(o[1]);
			memcpy( p->file, o.c_str()+2, n );
			p->file[n] = '\0';
			continue;
		}

		memcpy( options, o.c_str(), o.size() );
		options += o.size();
	}
	*options = DOP_END_OPTION;
}

////////////////////////////////////////

void replyDiscover( packet *p, packet_queue &q, uint32_t ip, uint32_t server_ip, const char *hostname )
{
	// Find the requested parameter list.
	std::set<char> requested;
	{
		std::vector<std::string> copts;
		extractOptions( p, copts );
		for ( std::string &o: copts )
		{
			if ( o[0] == DOP_PARAMETER_REQUEST_LIST )
			{
				for ( size_t i = 2; i < o.size(); ++i )
					requested.insert( o[i] );
			}
		}
	}

	// Create a reply packet
	packet *reply = q.alloc();
	memset( reply, 0, sizeof(packet) );
	reply->op = BOOT_REPLY;
	reply->htype = p->htype;
	reply->hlen = p->hlen;
	reply->xid = p->xid;
	memcpy( reply->chaddr, p->chaddr, p->hlen );
	uint8_t *hwaddr = reply->chaddr;

	// Find an IP address (prefer the one given, if any)
	{
		std::vector<uint32_t> ips = getIPAddresses( hwaddr, true );
		if ( ips.empty() )
		{
			syslog( LOG_INFO, "Unable to offer an address to '%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x'",
				hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5] );
			return;
		}
		if ( std::find( ips.begin(), ips.end(), ip ) == ips.end() )
			ip = ips[0];
	}

	reply->yiaddr = ip;


	// Find the requested options
	std::string lease;
	std::string server;

	std::vector<std::string> options;
	{
		std::vector<std::string> tmp;
		getOptions( ip, tmp );

		// Add the hostname
		std::string hostname;
		for ( std::string &o: tmp )
		{
			if ( o.empty() )
				continue;

			if ( o[0] == DOP_HOSTNAME )
			{
				hostname = o;
				continue;
			}

			if ( o[0] == DOP_IP_ADDRESS_LEASETIME )
			{
				lease = o;
				continue;
			}

			if ( o[0] == DOP_SERVER_IDENTIFIER )
			{
				server = o;
				continue;
			}

			if ( requested.find( o[0] ) != requested.end() )
				options.push_back( o );
		}

		if ( hostname.empty() )
		{
			try { hostname = ip_lookup( ip, false, false ); } catch ( ... ) {}
			if ( !hostname.empty() )
				options.push_back( format( "{0}{1}{2}", char(DOP_HOSTNAME), char(hostname.size()), hostname ) );
		}
		else
			options.push_back( hostname );

		std::sort( options.begin(), options.end() );
	}

	if ( server.empty() )
	{
		// Use the current server IP by default.
		server.push_back( DOP_SERVER_IDENTIFIER );
		server.push_back( 4 );
		server.append( reinterpret_cast<const char*>( &server_ip ), 4 );
	}

	// Add mandatory options
	if ( !lease.empty() )
		options.insert( options.begin(), lease );
	options.insert( options.begin(), server );
	options.insert( options.begin(), format( "{0,n3}", char(53), char(1), char(DHCP_OFFER) ) );

	fillOptions( reply, options );

	// Send the packet
	udp_socket client( server_ip, 67, true );
	client.send( INADDR_BROADCAST, 68, reply );

	syslog( LOG_INFO, "Offered %s to '%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x'",
		ip_string( reply->yiaddr ).c_str(), hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5] );

	q.free( reply );
}

////////////////////////////////////////

void replyRequest( packet *p, packet_queue &q, uint32_t ip, uint32_t server_ip, const char *hostname )
{
	// Find the requested parameter list.
	std::set<char> requested;
	{
		std::vector<std::string> copts;
		extractOptions( p, copts );
		for ( std::string &o: copts )
		{
			if ( o[0] == DOP_PARAMETER_REQUEST_LIST )
			{
				for ( size_t i = 2; i < o.size(); ++i )
					requested.insert( o[i] );
			}
		}
	}

	// Find an IP address (prefer the one given, if any)
	{
		const uint8_t *hwaddr = p->chaddr;
		std::vector<uint32_t> ips = getIPAddresses( hwaddr, true );
		if ( ips.empty() )
		{
			syslog( LOG_INFO, "Unable to offer an address to '%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x'",
				hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5] );
			return;
		}
		if ( std::find( ips.begin(), ips.end(), ip ) == ips.end() )
			ip = ips[0];
	}

	// Create a reply packet
	packet *reply = q.alloc();
	memset( reply, 0, sizeof(packet) );
	reply->op = BOOT_REPLY;
	reply->htype = p->htype;
	reply->hlen = p->hlen;
	reply->xid = p->xid;
	reply->yiaddr = ip;
	memcpy( reply->chaddr, p->chaddr, p->hlen );

	// Find the requested options
	std::string lease;
	std::string server;

	std::vector<std::string> options;
	{
		// Get the options
		std::vector<std::string> tmp;
		getOptions( ip, tmp );

		// Add the hostname
		std::string hostname;

		for ( std::string &o: tmp )
		{
			if ( o.empty() )
				continue;

			if ( o[0] == DOP_HOSTNAME )
			{
				hostname = o;
				continue;
			}

			if ( o[0] == DOP_IP_ADDRESS_LEASETIME )
			{
				lease = o;
				continue;
			}

			if ( o[0] == DOP_SERVER_IDENTIFIER )
			{
				server = o;
				continue;
			}

			if ( requested.find( o[0] ) != requested.end() )
				options.push_back( o );
		}
		
		if ( hostname.empty() )
		{
			try { hostname = ip_lookup( ip, false, false ); } catch ( ... ) {}
			if ( !hostname.empty() )
				options.push_back( format( "{0}{1}{2}", char(DOP_HOSTNAME), char(hostname.size()), hostname ) );
		}
		else
			options.push_back( hostname );

		std::sort( options.begin(), options.end() );
	}

	if ( server.empty() )
	{
		// Use the current server IP by default.
		server.push_back( DOP_SERVER_IDENTIFIER );
		server.push_back( 4 );
		server.append( reinterpret_cast<const char*>( &server_ip ), 4 );
	}

	// Add mandatory options
	uint32_t lease_time = 0;
	if ( lease.size() == 6 )
	{
		options.insert( options.begin(), lease );
		for ( int i = 2; i < 6; ++i )
			lease_time = ( lease_time << 8 ) + uint8_t(lease[i]);
	}
	options.insert( options.begin(), server );

	bool leased = true;
	if ( !acquireLease( ip, reply->chaddr, lease_time ) )
	{
		// Uhoh, not good.  Send a NAK
		options.clear();
		options.insert( options.begin(), format( "{0,n3}", char(53), char(1), char(DHCP_NAK) ) );
		leased = false;
	}
	else
		options.insert( options.begin(), format( "{0,n3}", char(53), char(1), char(DHCP_ACK) ) );

	fillOptions( reply, options );

	udp_socket client( server_ip, 67, true );
	client.send( INADDR_BROADCAST, 68, reply );

	uint8_t *hwaddr = reply->chaddr;

	if ( leased )
	{
		syslog( LOG_INFO, "Leased %s to '%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x'",
				ip_lookup( reply->yiaddr ).c_str(),
				hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5] );
	}
	else
	{
		syslog( LOG_INFO, "Refused %s to '%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x'",
				ip_lookup( reply->yiaddr ).c_str(),
				hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5] );
	}

	q.free( reply );
}

////////////////////////////////////////

void handleClientRequest( packet *p, uint32_t server_addr, packet_queue &queue )
{
	// Basic checks on the packet
	if ( p->htype != HWADDR_ETHER )
		error( "Can only handle ethernet hardware address" );

	if ( p->hlen != 6 )
		error( "Expected MAC address to be 6 bytes" );

	// Now process the options
	enum MsgType type = DHCP_UNKNOWN;
	uint32_t ipaddr = 0, server = 0;

	char hostname[1024] = { 0 };

	uint8_t *options = p->options;
	if ( options[0] == 0x63 && options[1] == 0x82 && options[2] == 0x53 && options[3] == 0x63 )
	{
		options += 4;

		while ( *options != DOP_END_OPTION )
		{
			switch ( *options )
			{
				case DOP_DHCP_MESSAGE_TYPE:
					if ( options[1] == 1 )
						type = MsgType(options[2]);
					else
					{
						syslog( LOG_ERR, "Invalid DHCP message type length" );
						return;
					}
					break;

				case DOP_REQUESTED_IP_ADDRESS:
					if ( options[1] == 4 )
						memcpy( &ipaddr, &options[2], 4 );
					else
					{
						syslog( LOG_ERR, "Invalid requested IP length" );
						return;
					}
					break;

				case DOP_SERVER_IDENTIFIER:
					if ( options[1] == 4 )
						memcpy( &server, &options[2], 4 );
					else
					{
						syslog( LOG_ERR, "Invalid server identifier length" );
						return;
					}
					break;

				case DOP_HOSTNAME:
				{
					strncpy( hostname, reinterpret_cast<const char *>( options+2 ), uint32_t(options[1]) );
					hostname[options[1]] = '\0';
					break;
				}

				default:
					break;
			}
			if ( *options != DOP_PADDING )
				options += 2 + options[1];
			else
				options++;
		}
	}
	else
		syslog( LOG_ERR, "Invalid DHCP magic cookie for options" );

	uint8_t *hwaddr = p->chaddr;
	switch ( type )
	{
		case DHCP_DISCOVER:
			syslog( LOG_INFO, "Got DISCOVER from '%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x'", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5] );
			replyDiscover( p, queue, ipaddr, server_addr, hostname );
			break;

		case DHCP_REQUEST:
			if ( server == server_addr || server == INADDR_ANY )
			{
				syslog( LOG_INFO, "Got REQUEST from '%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x' (for '%s' aka '%s')",
					hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5], ip_lookup( ipaddr ).c_str(), hostname );
				replyRequest( p, queue, ipaddr, server_addr, hostname );
			}
			else
			{
				syslog( LOG_INFO, "Ignore REQUEST for server %s from '%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x'",
						ip_lookup( server ).c_str(), hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5] );
			}
			break;

		case DHCP_RELEASE:
			if ( server == server_addr )
			{
				syslog( LOG_INFO, "Got RELEASE from '%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x'", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5] );
				releaseLease( p->yiaddr, hwaddr );
			}
			break;

		case DHCP_INFORM:
			syslog( LOG_INFO, "Got INFORM from '%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x'", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5] );
			break;

		case DHCP_DECLINE:
			syslog( LOG_INFO, "Got DECLINE from '%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x'", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5] );
			break;

		default:
			throw std::runtime_error( "Unknown DHCP message" );
	}
}

////////////////////////////////////////

void handler( uint32_t server_addr, packet_queue &queue )
{
	static std::mutex mutex;

	try
	{
		threadStartBackend();
	}
	catch ( std::exception &e )
	{
		syslog( LOG_CRIT, "Thread couldn't start properly: %s", e.what() );
		throw;
	}

	catch ( ... )
	{
		syslog( LOG_CRIT, "Thread couldn't start properly" );
		throw;
	}
	bool testing = false;
	{
		std::string test = configuration["testing"] ;
		testing = ( test == "yes" || test == "true" || test == "on" );
	}
	if ( testing )
		syslog( LOG_INFO, "Testing mode" );

	while ( packet *p = queue.wait() )
	{
		try
		{
			if ( testing )
			{
				std::unique_lock<std::mutex> lock( mutex );
				std::cout << "Packet:\n" << p << std::endl;
			}
			else if ( p->op == BOOT_REQUEST )
			{
				// Process the packet
				handleClientRequest( p, server_addr, queue );
			}
			else if ( p->op == BOOT_REPLY )
			{
				; // Ignore replies for now (always?)
			}
			else
				syslog( LOG_ERR, "Invalid BOOTP op code" );
		}
		catch ( std::exception &e )
		{
			syslog( LOG_ERR, "Error processing packet: %s", e.what() );
		}

		queue.free( p );
	}

	try
	{
		threadStopBackend();
	}
	catch ( std::exception &e )
	{
		syslog( LOG_ERR, "Thread couldn't shutdown properly: %s", e.what() );
		throw;
	}
	catch ( ... )
	{
		syslog( LOG_ERR, "Thread couldn't shutdown properly" );
		throw;
	}
}

////////////////////////////////////////

