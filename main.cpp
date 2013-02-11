

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

#include <arpa/inet.h>
#include <string.h>

#include "config.h"
#include "option.h"
#include "error.h"
#include "backend.h"
#include "format.h"
#include "server.h"
#include "udp_socket.h"
#include "packet.h"
#include "handler.h"

////////////////////////////////////////

void print_usage( const std::string &prog )
{
	std::cout << "Usage:\t" << prog << " [<config>] [<command> ...]\n";
	std::cout << "  <config> Configuration file as absolute path (starting with /)\n";
	std::cout << "  <command> Commend to execute (with arguments)\n";
	std::cout << "\nCommands:\n";
	std::cout << "  server [<pidfile>] - start a server (with optional pidfile)\n";
	std::cout << "  show <ip> - show options for <ip>\n";
	std::cout << "  option <ip> <ip> <option> - add option for IP range\n";
	std::cout << "  remove-option <ip> <ip> <option> - remove option for IP range\n";
	std::cout << "  host <ip> <mac> - add option for IP range\n";
	std::cout << "  remove-host <ip> - remove a host with a IP address\n";
	std::cout << "  list <mac> - list IP addresses for a MAC address\n";
	std::cout << "  available <mac> - list available IP addresses for a MAC address\n";
	std::cout << "  encode <option> - encode the option into a hex string\n";
	std::cout << "  decode <hex> - decode the hex option into something readable\n";
	std::cout << "  discover <ip> <mac> [<option> ...] - send a discover packet to an IP address\n";
	std::cout << "  monitor - listen for DHCP packets and show them\n";
	std::cout << "\nDHCP Options:\n";
	for ( auto opt: dhcp_options )
	{
		std::cout << "  " << opt.first;
		switch ( dhcp_types[opt.second] )
		{
			case TYPE_ADDRESS:
				std::cout << "(1.2.3.4)\n";
				break;
			case TYPE_ADDRESSES:
				std::cout << "(1.2.3.4,...)\n";
				break;
			case TYPE_HWADDR:
				std::cout << "(00:11:22:33:44:55)\n";
				break;
			case TYPE_STRING:
				std::cout << "(name)\n";
				break;
			case TYPE_UINT32:
				std::cout << "(1234)\n";
				break;
			case TYPE_UINT8:
				std::cout << "(12)\n";
				break;
			case TYPE_UINT8S:
				std::cout << "(12,...)\n";
				break;
		}
	}
}

////////////////////////////////////////

int main( int argc, char *argv[] )
{
	std::string config = "/etc/dhcpdb.conf";
	std::vector<std::string> command;

	for ( int i = 1; i < argc; ++i )
	{
		std::string arg( argv[i] );
		if ( arg.empty() )
			continue;

		if ( i == 1 && arg[0] == '/' )
			config = arg;
		else
			command.push_back( arg );
	}

	parse_config( config );

	// No command?
	if ( command.empty() )
	{
		print_usage( argv[0] );
		return 0;
	}

	if ( command[0] == "server" )
	{
		if ( command.size() > 2 )
			error( "Command 'server' has 1 optional argument: server <pidfile>" );

		if ( command.size() < 1 )
			command.push_back( std::string() );

		threadStartBackend();
		int ret = server( command[1] );
		threadStopBackend();
	}

	if ( command[0] == "show" )
	{
		threadStartBackend();
		if ( command.size() != 2 )
			error( "Command 'show' needs 1 arguments: show <ip>" );

		uint32_t ip = dns_lookup( command[1].c_str() );
		std::vector<std::string> options;
		getOptions( ip, options );
		bool addhost = true;
		for ( std::string &o: options )
		{
			if ( o.empty() )
				continue;
			if ( o[0] == DOP_HOSTNAME )
				addhost = false;
		}
		if ( addhost )
		{
			std::string hostname;
			try { hostname = ip_lookup( ip, false, false ); } catch ( ... ) {}
			if ( !hostname.empty() )
				options.push_back( format( "{0}{1}{2}", char(DOP_HOSTNAME), char(hostname.size()), hostname ) );
		}
		std::sort( options.begin(), options.end() );
		for ( const std::string &o: options )
			std::cout << print_options( o ) << '\n';
		if ( options.empty() )
			std::cout << "no options found\n";
		threadStopBackend();
	}
	else if ( command[0] == "option" )
	{
		threadStartBackend();
		if ( command.size() != 4 )
			error( "Command 'option' needs 3 arguments: option <ip> <ip> <option>" );

		uint32_t ip1 = dns_lookup( command[1].c_str() );
		uint32_t ip2 = dns_lookup( command[2].c_str() );
		std::string opt = parse_option( command[3] );
		addOption( ip1, ip2, opt );
		threadStopBackend();
	}
	else if ( command[0] == "remove-option" )
	{
		threadStartBackend();
		if ( command.size() != 4 )
			error( "Command 'remove-option' needs 3 arguments: remove-option <ip> <ip> <option>" );

		uint32_t ip1 = dns_lookup( command[1].c_str() );
		uint32_t ip2 = dns_lookup( command[2].c_str() );
		std::string opt = parse_option( command[3] );
		removeOption( ip1, ip2, opt );
		threadStopBackend();
	}
	else if ( command[0] == "host" )
	{
		threadStartBackend();
		if ( command.size() != 3 )
			error( "Command 'host' needs 2 arguments: host <ip> <mac>" );

		uint32_t ip = dns_lookup( command[1].c_str() );
		std::string mac = parse_mac( command[2] );
		addHost( ip, reinterpret_cast<const uint8_t*>( mac.data() ) );
		threadStopBackend();
	}
	else if ( command[0] == "remove-host" )
	{
		threadStartBackend();
		if ( command.size() != 2 )
			error( "Command 'remove-host' needs 1 arguments: remove-host <ip>" );

		uint32_t ip = dns_lookup( command[1].c_str() );
		removeHost( ip );
		threadStopBackend();
	}
	else if ( command[0] == "list" )
	{
		threadStartBackend();
		if ( command.size() != 2 )
			error( "Command 'list' needs 1 argument: list <mac>" );

		std::string mac = parse_mac( command[1] );
		std::vector<uint32_t> ips = getIPAddresses( reinterpret_cast<const uint8_t*>( mac.data() ) );
		for ( size_t i = 0; i < ips.size(); ++i )
			std::cout << as_hex<uint8_t>( reinterpret_cast<uint8_t*>(&ips[i]), 4, '.' ) << std::endl;
		if ( ips.empty() )
			std::cout << format( "no addresses found for {0,B16,w2,f0}", as_hex<char>( mac, ':' ) ) << std::endl;
		threadStopBackend();
	}
	else if ( command[0] == "available" )
	{
		threadStartBackend();
		if ( command.size() != 2 )
			error( "Command 'available' needs 1 argument: available <mac>" );

		std::string mac = parse_mac( command[1] );
		std::vector<uint32_t> ips = getIPAddresses( reinterpret_cast<const uint8_t*>( mac.data() ), true );
		for ( size_t i = 0; i < ips.size(); ++i )
			std::cout << ip_lookup( ips[i] ) << std::endl;
		if ( ips.empty() )
			std::cout << format( "no addresses found for {0,B16,w2,f0}", as_hex<char>( mac, ':' ) ) << std::endl;
		threadStopBackend();
	}
	else if ( command[0] == "decode" )
	{
		if ( command.size() != 2 )
			error( "Command 'decode' needs 1 argument: decode <hex>" );

		std::string o = print_options( from_hex( command[1] ) );
		std::cout << o << std::endl;
	}
	else if ( command[0] == "encode" )
	{
		if ( command.size() != 2 )
			error( "Command 'encode' needs 1 argument: encode <option>" );

		std::string o = parse_option( command[1] );
		std::cout << format( "{0,B16,w2,f0}", as_hex<char>( o ) ) << std::endl;
	}
	else if ( command[0] == "discover" )
	{
		if ( command.size() < 3 )
			error( "Command 'discover' needs 2 or more argument: discover <ip> <mac> [<options> ...]" );

		uint32_t addr = dns_lookup( command[1].c_str() );
		std::string mac = parse_mac( command[2] );

		packet p;
		memset( &p, 0, sizeof(p) );
		p.op = BOOT_REQUEST;
		p.htype = HWADDR_ETHER;
		p.hlen = 6;
		p.xid = 0xCAFEBEEF;
		memcpy( p.chaddr, mac.c_str(), 6 );

		std::vector<std::string> opts;
		opts.push_back( parse_option( "msgtype(1)" ) );
		opts.push_back( parse_option( "param_requested(1,3,6,12,15,54,66,67" ) );
		opts.push_back( parse_option( "vendorid(DHCPDB discover test)" ) );
		for ( size_t i = 3; i < command.size(); ++i )
			opts.push_back( parse_option( command[i] ) );
		fillOptions( &p, opts );

		udp_socket s( INADDR_ANY, 0, true );
		s.send( addr, 67, &p );
		std::cout << "Sent:\n" << &p << std::endl;
	}
	else if ( command[0] == "monitor" )
	{
		if ( command.size() != 1 )
			error( "Command 'monitor' needs no arguments: monitor" );

		udp_socket s( INADDR_ANY, 67, false );
		packet p;

		while ( 1 )
		{
			try
			{
				s.recv( &p );
				std::cout << "Received:\n" << &p << std::endl;
			}
			catch ( std::exception &e )
			{
				std::cout << "Error: " << e.what() << std::endl;
				break;
			}
			catch ( ... )
			{
				std::cout << "Error: unknown" << std::endl;
				break;
			}
		}
	}
	else
	{
		print_usage( argv[0] );
	}


	return 0;
}

