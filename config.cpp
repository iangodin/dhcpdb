
#include <map>
#include <string>
#include <stdint.h>
#include <iostream>
#include <fstream>

#include "config.h"
#include "format.h"
#include "error.h"
#include "strutils.h"

std::map<std::string,std::string> configuration;

std::map<std::string,int> dhcp_options;
std::map<int,std::string> dhcp_names;
std::map<int,std::vector<Type>> dhcp_args;

////////////////////////////////////////

void parse_config( const std::string &filename )
{
	std::ifstream file( filename );

	int count = 0;
	std::string line;
	while ( std::getline( file, line ) )
	{
		++count;
		if ( line.empty() )
			continue;
		if ( line[0] == '#' )
			continue;

		try
		{
			auto p = line.find_first_of( '=' );
			if ( p == 0 || p == std::string::npos || p == line.size() )
				error( "Expected '='" );

			std::string key( trim( line.substr( 0, p ) ) );
			std::string val( trim( line.substr( p + 1 ) ) );

			if ( ! is_number( key ) )
			{
				configuration[trim(key)] = trim( val );
			}
			else
			{
				int opt = std::stoi( key );
				if ( opt <= 0 || opt >= 255 )
					error( format( "Invalid DHCP option {0} at line {1}", opt, count ) );

				std::string name;
				std::vector<std::string> optargs;
				parse_function( val, name, optargs );

				std::vector<Type> args;
				for ( size_t i = 0; i < optargs.size(); ++i )
				{
					std::string type = optargs[i];

					if ( type.empty() )
						error( format( "No type at line {0}", count ) );

					if ( type == "ip" )
						args.push_back( TYPE_ADDRESS );
					else  if ( type == "mac" )
						args.push_back( TYPE_HWADDR );
					else  if ( type == "uint32" )
						args.push_back( TYPE_UINT32 );
					else  if ( type == "uint16" )
						args.push_back( TYPE_UINT16 );
					else  if ( type == "uint8" )
						args.push_back( TYPE_UINT8 );
					else  if ( type == "hex" )
					{
						if ( !args.empty() || optargs.size() > 1 )
							error( "Can only have a single 'hex' by itself in options" );
						args.push_back( TYPE_HEX );
					}
					else  if ( type == "string" )
					{
						if ( !args.empty() || optargs.size() > 1 )
							error( "Can only have a single 'string' by itself in options" );
						args.push_back( TYPE_STRING );
					}
					else  if ( type == "names" )
					{
						if ( !args.empty() || optargs.size() > 1 )
							error( "Can only have a single 'names' by itself in options" );
						args.push_back( TYPE_NAMES );
					}
					else  if ( type == "..." )
					{
						if ( i+1 != optargs.size() )
							error( "Expected '...' at the end of the argument list" );
						if ( optargs.size() == 1 )
							error( "Expected other type before '...'" );
						args.push_back( TYPE_MORE );
					}
					else
						error( format( "Unknown type '{0}' at line {1}", type, count ) );
				}

				dhcp_args[opt] = args;
				dhcp_options[name] = opt;
				dhcp_names[opt] = name;
			}
		}
		catch ( std::exception &e )
		{
			throw std::runtime_error( format( "Error at line {0}: {1}", count, e.what() ) );
		}
		catch ( ... )
		{
			throw std::runtime_error( format( "Error at line {0}: unknown", count ) );
		}
	}
}

