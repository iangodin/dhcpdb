
#include "strutils.h"

#include <stdexcept>

////////////////////////////////////////

void parse_function( const std::string &str, std::string &name, std::vector<std::string> &args )
{
	if ( str.empty() )
		throw std::invalid_argument( "empty function string" );

	size_t p = str.find_first_of( '(' );

	name = trim( str.substr( 0, p ) );

	size_t e = str.find_first_of( ",)", p );
	while ( e != std::string::npos )
	{
		args.push_back( trim( str.substr( p+1, e-p-1 ) ) );
		p = e;
		e = str.find_first_of( ",)", p+1 );
	}
}

////////////////////////////////////////

