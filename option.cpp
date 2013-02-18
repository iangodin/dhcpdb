
#include <arpa/inet.h>
#include <string>

#include "format.h"
#include "config.h"
#include "error.h"
#include "udp_socket.h"
#include "strutils.h"

////////////////////////////////////////

std::string pack_name( const std::string &name )
{
	std::string ret;
	size_t loc = 0;
	ret.push_back( '\0' );
	for ( size_t i = 0; i < name.size(); ++i )
	{
		if ( std::isalnum( name[i] ) )
		{
			ret.push_back( name[i] );
			ret[loc]++;
		}
		else if ( name[i] == '.' )
		{
			loc = ret.size();
			ret.push_back( '\0' );
		}
		else if ( !std::isspace( name[i] ) )
			error( "Invalid character in domain name" );
	}

	if ( ret.back() == '\0' )
		error( "Domain name ended with '.'" );

	if ( ret.empty() )
		error( "Domain name is empty." );

	ret.push_back( '\0' );

	return ret;
}

////////////////////////////////////////

void unpack_names( const std::string &str, std::vector<std::string> &n )
{
	std::string ret;

	for ( size_t i = 0; i < str.size(); )
	{
		uint8_t s = str[i++];
		if ( s == 0 )
		{
			if ( !ret.empty() )
				n.push_back( ret );
			ret.clear();
		}
		else
		{
			if ( !ret.empty() )
				ret.push_back( '.' );
			ret += str.substr( i, s );
			i += s;
		}
	}

	if ( !ret.empty() )
		n.push_back( ret );
}

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
	std::string name;
	std::vector<std::string> args;

	parse_function( opt, name, args );

	if ( dhcp_options.find( name ) == dhcp_options.end() )
		error( format( "Unknown DHCP option '{0}'", name ) );

	int o = dhcp_options[name];
	std::vector<Type> argtypes = dhcp_args[o];

	if ( argtypes.back() == TYPE_MORE )
	{
		argtypes.pop_back();
		while ( argtypes.size() < args.size() )
			argtypes.push_back( argtypes.back() );
	}
	if ( argtypes.size() == 1 && argtypes[0] == TYPE_NAMES )
	{
		while ( argtypes.size() < args.size() )
			argtypes.push_back( argtypes.back() );
	}

	if ( argtypes.size() != args.size() )
		error( format( "Expected {0} arguments, got {1} instead", argtypes.size(), args.size() ) );

	std::string ret;
	ret.push_back( o );
	ret.push_back( '\0' );

	size_t size = 0;

	for ( size_t i = 0; i < args.size(); ++i )
	{
		switch ( argtypes[i] )
		{
			case TYPE_ADDRESS:
			{
				size += 4;
				uint32_t ip = dns_lookup( args[i].c_str() );
				ret.append( std::string( reinterpret_cast<const char*>(&ip), 4 ) );
				break;
			}

			case TYPE_HWADDR:
				error( "Not yet implemented" );
				break;

			case TYPE_STRING:
				size += args[i].size();
				ret.append( args[i] );
				break;

			case TYPE_NAMES:
			{
				std::string tmp = pack_name( args[i] );
				ret.append( tmp );
				size += tmp.size();
				break;
			}

			case TYPE_UINT32:
			{
				size += 4;
				uint32_t ip = htonl( std::stoul( args[i] ) );
				ret.append( reinterpret_cast<const char *>(&ip), 4 );
				break;
			}

			case TYPE_UINT16:
			{
				size += 2;
				uint16_t n = htons( std::stoul( args[i] ) );
				ret.append( reinterpret_cast<const char*>( &n ), 2 );
				break;
			}

			case TYPE_UINT8:
			{
				size += 1;
				uint32_t n = std::stoul( args[i] );
				if ( n > 255 )
					error( format( "Number (argument {0}) too large for option {1}", i, name ) );
				ret.push_back( n );
				break;
			}

			case TYPE_HEX:
			{
				std::string hex = from_hex( args[i] );
				ret.push_back( hex.size() );
				ret.append( hex );
				break;
			}

			default:
				error( "Unknown option type" );
				break;
		}
	}

	ret[1] = size;

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
	ret.push_back( '(' );

	std::vector<Type> argtypes = dhcp_args[uint8_t(opt[0])];

	size_t p = 2;
	Type last = TYPE_MORE;
	for ( size_t i = 0; i < argtypes.size() && p != opt.size(); ++i )
	{
		if ( i > 0 )
			ret.push_back( ',' );
		ret.push_back( ' ' );

		Type atype = argtypes[i];
		if ( atype == TYPE_MORE )
		{
			atype = last;
			argtypes.push_back( TYPE_MORE );
		}

		if ( atype == TYPE_MORE )
			error( "Invalid option specification" );

		switch ( atype )
		{
			case TYPE_ADDRESS:
				if ( p+4 > opt.size() )
					error( "Not enough data for IP address" );
				ret += format( "{0}", as_hex<char>( &opt[p], 4, '.' ) );
				p += 4;
				break;

			case TYPE_HWADDR:
				error( "Not yet implemented" );
				break;

			case TYPE_UINT32:
			{
				if ( p+4 > opt.size() )
					error( "Not enough data for uint32" );
				uint32_t n = 0;
				for ( int i = 0; i < 4; ++i )
					n = ( n << 8 ) + uint8_t(opt[p+i]);
				ret += format( "{0}", n );
				p += 4;
				break;
			}

			case TYPE_UINT16:
			{
				if ( p+2 > opt.size() )
					error( "Not enough data for uint16" );
				uint32_t n = 0;
				for ( int i = 0; i < 2; ++i )
					n = ( n << 8 ) + uint8_t(opt[p+i]);
				ret += format( "{0}", n );
				p += 2;
				break;
			}

			case TYPE_UINT8:
			{
				if ( p+1 > opt.size() )
					error( "Not enough data for uint8" );
				uint32_t n = uint8_t(opt[p]);
				ret += format( "{0}", n );
				p += 1;
				break;
			}

			case TYPE_STRING:
			{
				size_t size = uint8_t( opt[1] );
				ret += opt.substr( p, size );
				p += size;
				break;
			}

			case TYPE_HEX:
			{
				if ( opt.size() < 3 )
					error( format( "Invalid option size {0}", opt.size() ) );

				size_t size = uint8_t( opt[1] );
				ret += format( "{0,B16,w2,f0}", as_hex<char>( opt.substr( 2, size ) ) );
				p += size;
				break;
			}

			case TYPE_NAMES:
			{
				std::vector<std::string> names;

				size_t size = uint8_t( opt[1] );
				unpack_names( opt.substr( p, size ), names );
				for ( size_t i = 0; i < names.size(); ++i )
				{
					if ( i > 0 )
						ret.append( ", " );
					ret += names[i];
				}
				p += size;
				break;
			}

			default:
				error( "Unknown option type" );
				break;
		}
		last = atype;
	}
	ret += " )";

	return ret;
}

