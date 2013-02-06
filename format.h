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

#pragma once

#include <tuple>
#include <string>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>

////////////////////////////////////////

template<typename T>
struct as_hex
{
	as_hex( const T *t, size_t n, char s = '\0' ) : value( t ), size( n ), sep( s ) {};
	as_hex( const T &t, char s = '\0' ) : value( &t ), size( 1 ), sep( s ) {};
	as_hex( const std::vector<T> &t, char s = '\0' ) : value( t.data() ), size( t.size() ), sep( s ) {};
	as_hex( const std::basic_string<T> &t, char s = '\0' ) : value( t.data() ), size( t.size() ), sep( s ) {};

	const T *value; 
	size_t size;
	char sep;
};

template<typename T>
inline std::ostream &operator<<( std::ostream &out, const as_hex<T> &n )
{
	size_t w = out.width();
	out.setf( std::ios_base::right );
	for ( size_t i = 0; i < n.size; ++i )
	{
		if ( n.sep && i > 0 )
			out << n.sep;
		out.width( w );
		out << uint16_t( uint8_t(n.value[i]) );
	}
	return out;
}

////////////////////////////////////////

template<typename ... Args>
class format_holder
{
public:
	format_holder( std::string fmt, const Args &...args )
		: _fmt( std::move( fmt ) ), _args( std::tie( args... ) )
	{
	}

	operator std::string()
	{
		std::stringstream str;
		str << *this;
		return str.str();
	}

	template <typename CharT>
	void output( std::basic_ostream<CharT> &out, size_t x ) const
	{
		get_arg<CharT, 0, std::tuple_size<std::tuple<Args...>>::value>::output( out, _args, x );
	}

	template <typename CharT>
	void output_n( std::basic_ostream<CharT> &out, size_t x, size_t n, char sep ) const
	{
		get_arg<CharT, 0, std::tuple_size<std::tuple<Args...>>::value>::output_n( out, _args, x, n, sep );
	}

	const char *format_begin( void ) const { return _fmt.c_str(); }
	const char *format_end( void ) const { return _fmt.c_str() + _fmt.size(); }

private:
	template <typename CharT, size_t I, size_t N>
	struct get_arg
	{
		typedef get_arg<CharT,I+1,N-1> base;

		template<typename Tuple>
		static void output( std::basic_ostream<CharT> &out, const Tuple &t, size_t x )
		{
			if ( x == I )
			{
				out << std::get<I>( t );
				return;
			}
			base::output( out, t, x );
		}

		template<typename Tuple>
		static void output_n( std::basic_ostream<CharT> &out, const Tuple &t, size_t x, size_t n, char sep )
		{
			if ( x == I )
			{
				for ( size_t i = 0; i < n; ++i )
				{
					if ( i > 0 )
						out << sep;
					out << (std::get<I>( t )[i]);
				}
				return;
			}
			base::output( out, t, x );
		}
	};

	template <typename CharT, size_t I>
	struct get_arg<CharT,I,0>
	{
		template<typename Tuple>
		static void output( std::basic_ostream<CharT> &, const Tuple &, size_t )
		{
			throw std::runtime_error( "Invalid fmt format string or missing argument" );
		}

		template<typename Tuple>
		static void output_n( std::basic_ostream<CharT> &, const Tuple &, size_t, size_t, char )
		{
			throw std::runtime_error( "Invalid fmt format string or missing argument" );
		}
	};

	std::string _fmt;
	const std::tuple<Args...> _args;
};

////////////////////////////////////////

template<typename ... Args>
format_holder<Args...> format( std::string fmt, const Args &...args )
{
	return format_holder<Args...>( std::move( fmt ), args... );
}

////////////////////////////////////////

class format_specifier
{
public:
	/// Parse the format specifier given.
	format_specifier( const char *&fmt, const char *end );

	int index;
	int width;
	int base;
	int precision;
	int alignment;
	char fill;
	char separator;
	bool upper_case;
	bool show_plus;
	int count;

	void apply( std::ostream &out );

	static bool begin( const char * &fmt, const char *end );

private:
	static int parse_number( const char * &fmt, const char *end );
};

////////////////////////////////////////

template<typename CharT, typename ... Args>
std::basic_ostream<CharT> &operator<<( std::basic_ostream<CharT> &out, const format_holder<Args...> &fmt )
{
	const char *start = fmt.format_begin();
	const char *end = fmt.format_end();
	const char *prev = start;

	while ( format_specifier::begin( start, end ) )
	{
		out.write( prev, int( start - prev ) );
		std::ios::fmtflags flags( out.flags() );

		format_specifier spec( start, end );
		spec.apply( out );

		for ( int i = 0; i < spec.count; ++i )
		{
			if ( i > 0 && spec.separator != '\0' )
				out << spec.separator;
			fmt.output( out, size_t(spec.index + i) );
		}
		prev = start + 1;

		out.flags( flags );
	}
	out.write( prev, int( start - prev ) );

	return out;
}

////////////////////////////////////////

// vim:ft=cpp:
