//
// Copyright (c) 2012 Ian Godin
//
// See LICENSE.txt for full license
//

#pragma once 

#include <string>
#include <algorithm>

////////////////////////////////////////

inline std::string ltrim( std::string s )
{
	s.erase( s.begin(), std::find_if( s.begin(), s.end(), std::not1( std::ptr_fun<int, int>(std::isspace) ) ) );
	return s;
}

////////////////////////////////////////

inline std::string rtrim( std::string s )
{
	s.erase( std::find_if( s.rbegin(), s.rend(), std::not1( std::ptr_fun<int, int>(std::isspace) ) ).base(), s.end() );
	return s;
}

////////////////////////////////////////

inline std::string trim( std::string s )
{
	return ltrim( rtrim( s ) );
}

////////////////////////////////////////

inline bool is_number( const std::string &s )
{
	return !s.empty() && std::find_if( s.begin(), s.end(), [](char c) { return !std::isdigit(c); } ) == s.end();
}

////////////////////////////////////////

void parse_function( const std::string &str, std::string &name, std::vector<std::string> &args );

////////////////////////////////////////

