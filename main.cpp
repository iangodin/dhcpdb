

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

#include <arpa/inet.h>
#include <string.h>
#include <syslog.h>

#include "config.h"
#include "option.h"
#include "error.h"
#include "backend.h"
#include "format.h"
#include "server.h"
#include "lookup.h"
#include "udp_socket.h"
#include "packet.h"
#include "handler.h"

void print_usage( const std::string &prog );
int safemain( int argc, char *argv[] );

////////////////////////////////////////

void print_usage( const std::string &prog )
{
	std::cout << "Usage:\t" << prog << " [<config>] [<command> ...]\n";
	std::cout << "  <config> Configuration file as absolute path (starting with /)\n";
	std::cout << "  <command> Commend to execute (with arguments)\n";
	std::cout << "\nCommands:\n";
	std::cout << "  server [<pidfile>] - start a server (with optional pidfile)\n";
	std::cout << "  options [<ip>] - show options for <ip> (or all when no ip)\n";
	std::cout << "  add-option <ip> [<ip>] <option> - add option for IP range\n";
	std::cout << "  replace-option <ip> [<ip>] <option> - replace option for IP range\n";
	std::cout << "  remove-option <ip> [<ip>] <option> - remove option for IP range\n";
	std::cout << "  add-host <ip> <mac> - add option for IP range\n";
	std::cout << "  replace-host <ip> [<new_ip>] <mac> - replace the given IP with a new MAC (and IP) address\n";
	std::cout << "  remove-host <ip> - remove a host with a IP address\n";
	std::cout << "  leases - list all leases\n";
	std::cout << "  list-all [<mac>] - list IP addresses (for a MAC address)\n";
	std::cout << "  list-available <mac> - list available IP addresses for a MAC address\n";
	std::cout << "  encode <option> ... - encode the option into a hex string\n";
	std::cout << "  decode <hex> ... - decode the hex option into something readable\n";
	std::cout << "  discover <ip> <mac> [<option> ...] - send a discover packet to an IP address\n";
	std::cout << "  monitor - listen for DHCP packets and show them\n";
	std::cout << "\nDHCP Options:\n";

	for ( auto opt: dhcp_options )
	{
		std::vector<Type> &args = dhcp_args[opt.second];
		std::cout << "  " << opt.first << '(';
		bool first = true;
		for ( auto t: args )
		{
			if ( first )
				first = false;
			else
				std::cout << ',';
			std::cout << ' ';

			switch ( t )
			{
				case TYPE_ADDRESS:
					std::cout << "1.2.3.4";
					break;
				case TYPE_HWADDR:
					std::cout << "00:11:22:33:44:55";
					break;
				case TYPE_STRING:
					std::cout << "something";
					break;
				case TYPE_UINT32:
					std::cout << "123456";
					break;
				case TYPE_UINT16:
					std::cout << "1234";
					break;
				case TYPE_UINT8:
					std::cout << "12";
					break;
				case TYPE_HEX:
					std::cout << "0123456789ABCDEF";
					break;
				case TYPE_NAMES:
					std::cout << "domain.com";
					break;
				case TYPE_MORE:
					std::cout << "...";
					break;
			}
		}
		std::cout << " )\n";
	}
}

////////////////////////////////////////

int safemain( int argc, char *argv[] )
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
		else if ( i == 1 && arg[0] == '.' )
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

	if ( command[0] == "options" )
	{
		threadStartBackend();
		if ( command.size() > 2 )
			error( "Command 'options' needs at most 1 arguments: options [<ip>]" );

		if ( command.size() == 2 )
		{
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
		else
		{
			std::vector<std::tuple<uint32_t, uint32_t, std::string>> options;
			getAllOptions( options );
			for ( auto opt: options )
				std::cout << format( "{0}\t{1}\t{2}", ip_string( std::get<0>( opt ) ), ip_string( std::get<1>( opt ) ), print_options( std::get<2>( opt ) ) ) << std::endl;
		}
	}
	else if ( command[0] == "add-option" || command[0] == "replace-option" )
	{
		threadStartBackend();
		if ( command.size() != 3 && command.size() != 4 )
			error( "Command 'option' needs 2 or 3 arguments: option <ip> [<ip>] <option>" );

		uint32_t ip1 = dns_lookup( command[1].c_str() );
		uint32_t ip2 = ip1;
		if ( command.size() == 4 )
			ip2 = dns_lookup( command[2].c_str() );
		std::string opt = parse_option( command.back() );
		addOption( ip1, ip2, opt, command[0] == "replace-option" );
		std::cout << format( "{0}\t{1}\t{2}", ip_string( ip1 ), ip_string( ip2 ), print_options( opt ) ) << std::endl;
		threadStopBackend();
	}
	else if ( command[0] == "remove-option" )
	{
		threadStartBackend();
		if ( command.size() != 3 && command.size() != 4  )
			error( "Command 'remove-option' needs 2 or 3 arguments: remove-option <ip> [<ip>] <option>" );

		uint32_t ip1 = dns_lookup( command[1].c_str() );
		uint32_t ip2 = ip1;
		if ( command.size() == 4 )
			ip2 = dns_lookup( command[2].c_str() );
		std::string opt = parse_option( command.back() );
		removeOption( ip1, ip2, opt );
		threadStopBackend();
	}
	else if ( command[0] == "add-host" )
	{
		threadStartBackend();
		if ( command.size() != 3 )
			error( "Command 'add-host' needs 2 arguments: add-host <ip> <mac>" );

		uint32_t ip = dns_lookup( command[1].c_str() );
		std::string mac = parse_mac( command[2] );
		addHost( ip, reinterpret_cast<const uint8_t*>( mac.data() ) );
		std::cout << format( "{0}\t{1}\t{2,B16,w2,f0}", ip_string( ip ), ip_lookup( ip ), as_hex<char>( mac, '-' ) ) << std::endl;
		threadStopBackend();
	}
	else if ( command[0] == "replace-host" )
	{
		threadStartBackend();
		if ( command.size() > 4 || command.size() < 3 )
			error( "Command 'replace-host' needs 2 or 3 arguments: replace-host <ip> [<new_ip>] <mac>" );

		uint32_t ip = dns_lookup( command[1].c_str() );
		removeHost( ip );

		if ( command.size() == 4 )
			ip = dns_lookup( command[2].c_str() );
		std::string mac = parse_mac( command.back() );
		addHost( ip, reinterpret_cast<const uint8_t*>( mac.data() ) );
		std::cout << format( "{0}\t{1}\t{2,B16,w2,f0}", ip_string( ip ), ip_lookup( ip ), as_hex<char>( mac, '-' ) ) << std::endl;

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
	else if ( command[0] == "leases" )
	{
		threadStartBackend();

		if ( command.size() > 1 )
			error( "Command 'leases' needs no argument: leases" );

		std::vector< std::tuple<uint32_t,std::string,std::string> > leases;
		getAllLeases( leases );
		for ( auto l: leases )
			std::cout << format( "{0}\t{1}\t{2,B16,w2,f0}\t{3}", ip_string( std::get<0>( l ) ), ip_lookup( std::get<0>( l ) ), as_hex<char>( std::get<1>( l ), '-' ), std::get<2>( l ) ) << std::endl;

		threadStopBackend();
	}
	else if ( command[0] == "list-all" )
	{
		threadStartBackend();
		if ( command.size() > 2 )
			error( "Command 'list-all' needs at most 1 argument: list-all [<mac>]" );

		if ( command.size() > 1 )
		{
			std::string mac = parse_mac( command[1] );
			std::vector<uint32_t> ips = getIPAddresses( reinterpret_cast<const uint8_t*>( mac.data() ) );
			for ( size_t i = 0; i < ips.size(); ++i )
				std::cout << as_hex<uint8_t>( reinterpret_cast<uint8_t*>(&ips[i]), 4, '.' ) << std::endl;
			if ( ips.empty() )
				std::cout << format( "no addresses found for {0,B16,w2,f0}", as_hex<char>( mac, '-' ) ) << std::endl;
		}
		else
		{
			std::vector< std::pair<uint32_t,std::string> > hosts;
			getAllHosts( hosts );
			for ( auto h: hosts )
				std::cout << format( "{0}\t{1}\t{2,B16,w2,f0}", ip_string( h.first ), ip_lookup( h.first ), as_hex<char>( h.second, '-' ) ) << std::endl;
		}

		threadStopBackend();
	}
	else if ( command[0] == "list-available" )
	{
		threadStartBackend();
		if ( command.size() != 2 )
			error( "Command 'list-available' needs 1 argument: list-available <mac>" );

		std::string mac = parse_mac( command[1] );
		std::vector<uint32_t> ips = getIPAddresses( reinterpret_cast<const uint8_t*>( mac.data() ), true );
		for ( size_t i = 0; i < ips.size(); ++i )
			std::cout << ip_lookup( ips[i] ) << std::endl;
		if ( ips.empty() )
			std::cout << format( "no addresses found for {0,B16,w2,f0}", as_hex<char>( mac, '-' ) ) << std::endl;
		threadStopBackend();
	}
	else if ( command[0] == "decode" )
	{
		if ( command.size() < 2 )
			error( "Command 'decode' needs at least 1 argument: decode <hex> ..." );

		for ( size_t i = 1; i < command.size(); ++i )
		{
			std::string o = print_options( from_hex( command[i] ) );
			std::cout << o << std::endl;
		}
	}
	else if ( command[0] == "encode" )
	{
		if ( command.size() < 2 )
			error( "Command 'encode' needs at least 1 argument: encode <option> ..." );

		for ( size_t i = 1; i < command.size(); ++i )
		{
			std::string o = parse_option( command[i] );
			std::cout << format( "{0,B16,w2,f0}", as_hex<char>( o ) ) << std::endl;
		}
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
		if ( command.size() > 2 )
			error( "Command 'monitor' needs at most 1 argument: monitor [<ip>]" );

		uint32_t ipaddr = INADDR_ANY;
		if ( command.size() > 1 )
			ipaddr = dns_lookup( command[1].c_str() );

		udp_socket s( ipaddr, 67, false );
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

////////////////////////////////////////

int main( int argc, char *argv[] )
{
	try
	{
		return safemain( argc, argv );
	}
	catch ( std::exception &e )
	{
		std::cout << "Fatal error: " << e.what() << std::endl;
	}
	catch ( ... )
	{
		std::cout << "Fatal error: unknown" << std::endl;
	}

	return -1;
}

