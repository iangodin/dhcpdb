//
// Copyright (c) 2012 Ian Godin
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//


#include "packet.h"
#include "format.h"
#include "option.h"
#include "lookup.h"

#include <arpa/inet.h>

#include <array>
#include <iomanip>
#include <sstream>

namespace
{

uint32_t fromOption4( const uint8_t *v )
{
	return (
		( (uint32_t)v[0] << 24 ) +
		( (uint32_t)v[1] << 16 ) +
		( (uint32_t)v[2] <<  8 ) +
		( (uint32_t)v[3] <<  0 ) );
}

uint32_t fromOption2( const uint8_t *v )
{
	return ( ( (uint32_t)v[0] <<  8 ) + ( (uint32_t)v[1] <<  0 ) );
}


std::string hexblob( const uint8_t *b, int n )
{
	std::stringstream str;
	int i;
	for ( i = 0; i < n; ++i )
		str << format( "{0,b16,f0,w2}", uint32_t(b[i]) );

	return str.str();
}

std::array<const char *,6> arch =
{{
	"Intel Architecture PC",
	"NEC PC-9800",
	"Intel Architecture 64 PC",
	"DEC Alpha",
	"ARCx86",
	"Intel Lean Client"
 }};

}

// Debugging function.
std::ostream &operator<<( std::ostream &out, const packet *p )
{
	// The BOOTP op code
	switch ( p->op )
	{
		case BOOT_REQUEST: out << "  request\n"; break;
		case BOOT_REPLY: out << "  reply\n"; break;
		default: out << "  unknown\n"; break;
	}

	// The hardware address
	switch ( p->htype )
	{
		case HWADDR_ETHER: out << "  hwaddr(ethernet"; break;
		case HWADDR_IEEE802: out << "  hwaddr(ieee_802"; break;
		case HWADDR_FDDI: out << "  hwaddr(fddi"; break;
		default: out << "  hwaddr(unknown"; break;
	}

	out << "," << hexblob( p->chaddr, p->hlen ) << ")\n";

	// Hops?  For BOOTP relay agent
	if ( p->hops != 0 )
		out << "  hops(" << uint32_t(p->hops) << ")\n";

	// Client unique ID
	out << "  xid(" << p->xid << ")\n";

	out << "  seconds(" << p->secs << ")\n";
	out << "  flags(" << ( p->flags == 0 ? "no broadcast" : "broadcast" ) << ")\n";
	out << "  ciaddr(" << ip_lookup( p->ciaddr ) << ")\n";
	out << "  yiaddr(" << ip_lookup( p->yiaddr ) << ")\n";
	out << "  siaddr(" << ip_lookup( p->siaddr ) << ")\n";
	out << "  giaddr(" << ip_lookup( p->giaddr ) << ")\n";


	out << "  server(" << p->sname << ")\n";
	out << "  bootfile(" << p->file << ")\n";

	// Check magic cookie
	const uint8_t *options = p->options;
	const uint8_t *end = p->options + 312;
	if ( options[0] == 0x63 && options[1] == 0x82 && options[2] == 0x53 && options[3] == 0x63 )
	{
		options += 4; // Skip cookie

		while( *options != DOP_END_OPTION && options < end )
		{
			if ( options[0] != 0 )
			{
				size_t n = options[1];
				out << "  " << uint32_t(options[0]) << ": " << print_options( std::string( reinterpret_cast<const char*>( options ), n + 2 ) ) << '\n';
				options += ( 2 + options[1] );
			}
			else
				options++;
		}
	}
	else
		out << "  Invalid magic option cookie\n";

	return out;
}

