
#include <map>
#include <string>
#include <stdint.h>
#include <iostream>
#include <fstream>

#include "config.h"
#include "format.h"
#include "error.h"

std::map<std::string,std::string> configuration;

std::map<std::string,int> dhcp_options;
std::map<int,std::string> dhcp_names;
std::map<int,Type> dhcp_types;

void parse_config( const std::string &filename )
{
	std::ifstream file( filename );

	std::string delim( "=:" );

	int count = 0;
	std::string line;
	while ( std::getline( file, line ) )
	{
		++count;
		if ( line.empty() )
			continue;
		if ( line[0] == '#' )
			continue;

		auto p = line.find_first_of( delim );
		if ( p == 0 || p == std::string::npos || p == line.size() )
			error( format( "Error in configuration at line {0}", count ) );

		if ( line[p] == '=' )
		{
			configuration[line.substr( 0, p )] = line.substr( p + 1 );
		}
		else
		{
			std::string optname = line.substr( 0, p );
			std::string type = line.substr( p + 1 );
			int opt = std::stoi( type, &p );
			type = type.substr( p );
			type = type.substr( type.find_first_not_of( ' ' ) );

			if ( opt <= 0 || opt >= 255 )
				error( format( "Invalid DHCP option {0} at line {1}", opt, count ) );

			if ( type.empty() )
				error( format( "No type at line {0}", count ) );

			if ( type == "ip" )
				dhcp_types[opt] = TYPE_ADDRESS;
			else  if ( type == "ips" )
				dhcp_types[opt] = TYPE_ADDRESSES;
			else  if ( type == "mac" )
				dhcp_types[opt] = TYPE_HWADDR;
			else  if ( type == "string" )
				dhcp_types[opt] = TYPE_STRING;
			else  if ( type == "uint32" )
				dhcp_types[opt] = TYPE_UINT32;
			else  if ( type == "uint16" )
				dhcp_types[opt] = TYPE_UINT16;
			else  if ( type == "uint8" )
				dhcp_types[opt] = TYPE_UINT8;
			else  if ( type == "uint8s" )
				dhcp_types[opt] = TYPE_UINT8S;
			else  if ( type == "hex" )
				dhcp_types[opt] = TYPE_HEX;
			else
				error( format( "Unknown type '{0}' at line {1}", type, count ) );

			dhcp_options[optname] = opt;
			dhcp_names[opt] = optname;
		}
	}
}

