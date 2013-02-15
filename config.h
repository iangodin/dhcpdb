
#pragma once

#include <map>
#include <string>
#include <vector>

extern std::map<std::string,std::string> configuration;

enum Type
{
	TYPE_ADDRESS,
	TYPE_HWADDR,
	TYPE_STRING,
	TYPE_UINT32,
	TYPE_UINT16,
	TYPE_UINT8,
	TYPE_HEX,
	TYPE_NAMES,
	TYPE_MORE,
};

extern std::map<std::string,int> dhcp_options;
extern std::map<int,std::string> dhcp_names;
extern std::map<int,std::vector<Type>> dhcp_args;

void parse_config( const std::string &filename );
