
#pragma once

#include <map>
#include <string>

extern std::map<std::string,std::string> configuration;

enum Type
{
	TYPE_ADDRESS,
	TYPE_ADDRESSES,
	TYPE_HWADDR,
	TYPE_STRING,
	TYPE_UINT32,
	TYPE_UINT16,
	TYPE_UINT8,
	TYPE_UINT8S,
	TYPE_HEX,
};

extern std::map<std::string,int> dhcp_options;
extern std::map<int,std::string> dhcp_names;
extern std::map<int,Type> dhcp_types;

void parse_config( const std::string &filename );
