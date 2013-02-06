
#include <arpa/inet.h>
#include <string>

#include "format.h"
#include "config.h"
#include "error.h"
#include "udp_socket.h"

////////////////////////////////////////

std::string from_hex( const std::string &h )
{
	std::string ret;
	for ( size_t i = 0; i+1 < h.size(); i += 2 )
		ret.push_back( std::stoul( h.substr( i, 2 ), NULL, 16 ) );
	return ret;
}

////////////////////////////////////////

std::string parse_mac( const std::string &opt )
{
	std::string ret( 6, '\0' );

	size_t p = 0;
	for ( size_t i = 0; i < ret.size(); ++i )
	{
		size_t tmp = p;
		uint32_t v = std::stoi( opt.substr( p ), &tmp, 16 );
		ret[i] = v;
		p += tmp + 1;
	}

	return ret;

}

////////////////////////////////////////

std::string parse_option( const std::string &opt )
{
	size_t p = opt.find_first_of( '(' );

	std::string name = opt.substr( 0, p );
	if ( dhcp_options.find( name ) == dhcp_options.end() )
		error( format( "Unknown DHCP option '{0}'", name ) );

	std::string ret;
	int o = dhcp_options[name];

	ret.push_back( o );

	std::vector<std::string> args;
	size_t e = opt.find_first_of( ",)", p );
	while ( e != std::string::npos )
	{
		args.push_back( opt.substr( p+1, e-p-1 ) );
		p = e;
		e = opt.find_first_of( ",)", p+1 );
	}

	switch ( dhcp_types[o] )
	{
		case TYPE_ADDRESS:
		{
			if ( args.size() != 1 )
				error( format( "Expected an IP address for option {0}", name ) );
			ret.push_back( 4 );

			uint32_t ip = dns_lookup( args[0].c_str() );
			ret.append( std::string( reinterpret_cast<const char*>(&ip), 4 ) );
			break;
		}

		case TYPE_ADDRESSES:
		{
			if ( args.size() < 1 )
				error( format( "Expected IP addresses for option {0}", name ) );
			ret.push_back( 4 * args.size() );

			for ( std::string &a: args )
			{
				uint32_t ip = dns_lookup( a.c_str() );
				ret.append( reinterpret_cast<const char*>(&ip), 4 );
			}
			break;
		}

		case TYPE_HWADDR:
			error( "Not yet implemented" );
			break;

		case TYPE_STRING:
			if ( args.size() != 1 )
				error( format( "Expected a string for option {0}", name ) );
			ret.push_back( args[0].size() );
			ret.append( args[0] );
			break;

		case TYPE_UINT32:
		{
			if ( args.size() < 1 )
				error( format( "Expected a number for option {0}", name ) );
			ret.push_back( 4 );

			uint32_t ip = std::stoul( args[0] );
			ret.append( reinterpret_cast<const char *>(&ip), 4 );
			break;
		}

		case TYPE_UINT16:
		{
			if ( args.size() < 1 )
				error( format( "Expected a number for option {0}", name ) );
			ret.push_back( 2 );

			uint16_t n = htons( std::stoul( args[0] ) );
			ret.append( reinterpret_cast<const char*>( &n ), 2 );
			break;
		}

		case TYPE_UINT8:
		{
			if ( args.size() < 1 )
				error( format( "Expected a number for option {0}", name ) );
			ret.push_back( 1 );
			uint32_t n = std::stoul( args[0] );
			if ( n > 255 )
				error( format( "Number too large for option {0}", name ) );
			ret.push_back( n );
			break;
		}

		case TYPE_UINT8S:
		{
			if ( args.size() < 1 )
				error( format( "Expected numbers for option {0}", name ) );
			ret.push_back( args.size() );
			for ( size_t i = 0; i < args.size(); ++i )
			{
				uint32_t n = std::stoul( args[i] );
				if ( n > 255 )
					error( format( "Number too large for option {0}", name ) );
				ret.push_back( n );
			}
			break;
		}

		case TYPE_HEX:
		{
			if ( args.size() != 1 )
				error( format( "Expected hex string for option {0}", name ) );
			ret.push_back( args.size() );
			ret.append( from_hex( opt.substr( 2 ) ) );
			break;
		}
		default:
			error( "Unknown option type" );
			break;
	}

	return ret;
}

////////////////////////////////////////

std::string print_options( const std::string &opt )
{
	std::string ret;

	if ( opt.empty() )
		error( "Invalid empty option" );

	auto name = dhcp_names.find( uint8_t(opt[0]) );
	if ( name == dhcp_names.end() )
	{
		ret = format( "{0,B16,w2,f0}", as_hex<char>( opt ) );
		return ret;
	}

	ret += name->second;
	ret += "(";

	switch ( dhcp_types[ uint32_t(uint8_t(opt[0])) ] )
	{
		case TYPE_ADDRESS:
			if ( opt.size() < 6 )
				error( format( "Invalid option size {0}", opt.size() ) );
			ret += format( "{0}", as_hex<char>( &opt[2], 4, '.' ) );
			ret += ")";
			break;

		case TYPE_ADDRESSES:
			if ( ( opt.size() - 2 ) % 4 != 0 && opt.size() >= 6 )
				error( format( "Invalid option size {0}", opt.size() ) );
			for ( int i = 2; i + 4 <= opt.size(); i+=4 )
			{
				if ( i > 2 )
					ret += ",";
				ret += format( "{0}", as_hex<char>( &opt[i], 4, '.' ) );
			}
			ret += ")";
			break;

		case TYPE_HWADDR:
			break;

		case TYPE_STRING:
			ret += opt.substr( 2, size_t(uint8_t(opt[1])) );
			ret += ")";
			break;

		case TYPE_UINT32:
		{
			if ( opt.size() != 6 )
				error( format( "Invalid option size {0}", opt.size() ) );
			uint32_t n = 0;
			for ( int i = 2; i < 6; ++i )
				n = ( n << 8 ) + uint8_t(opt[i]);
			ret += format( "{0})", n );
			break;
		}

		case TYPE_UINT16:
		{
			if ( opt.size() != 4 )
				error( format( "Invalid option size {0}", opt.size() ) );
			uint32_t n = 0;
			for ( int i = 2; i < 4; ++i )
				n = ( n << 8 ) + uint8_t(opt[i]);
			ret += format( "{0})", n );
			break;
		}

		case TYPE_UINT8:
		{
			if ( opt.size() != 3 )
				error( format( "Invalid option size {0}", opt.size() ) );
			uint32_t n = uint8_t(opt[2]);
			ret += format( "{0})", n );
			break;
		}

		case TYPE_UINT8S:
		{
			if ( opt.size() < 3 )
				error( format( "Invalid option size {0}", opt.size() ) );
			for ( size_t i = 2; i < opt.size(); ++i )
			{
				if ( i > 2 )
					ret.push_back( ',' );
				uint32_t n = uint8_t(opt[i]);
				ret += format( "{0}", n );
			}
			ret.push_back( ')' );
			break;
		}

		case TYPE_HEX:
		{
			if ( opt.size() < 3 )
				error( format( "Invalid option size {0}", opt.size() ) );
			ret += format( "{0,B16,w2,f0}", as_hex<char>( opt.substr( 2, opt[1] ) ) );
			ret.push_back( ')' );
			break;
		}

		default:
			error( "Unknown option type" );
			break;
	}

	return ret;
}

