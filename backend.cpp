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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <mysql/mysql.h>

#include <mutex>
#include <map>
#include <thread>

#include "backend.h"
#include "error.h"
#include "format.h"
#include "guard.h"

namespace
{
	std::mutex db_mutex;
	std::map<std::thread::id,MYSQL*> dbs;
}

////////////////////////////////////////

void threadStartBackend( void )
{
	std::unique_lock<std::mutex> lock( db_mutex );

	std::string dbhost = configuration["dbhost"];
	std::string database = configuration["database"];
	std::string dbuser = configuration["dbuser"];
	std::string dbpassword = configuration["dbpassword"];


	if ( dbhost.empty() || database.empty() || dbuser.empty() || dbpassword.empty() )
		error( "Invalid configuration file" );

	mysql_thread_init();
	MYSQL *db = mysql_init( NULL );
	if ( db == NULL )
		error( "Unable to init library" );

	my_bool reconnect = 1;
	unsigned int protocol = MYSQL_PROTOCOL_TCP;
	mysql_options( db, MYSQL_OPT_RECONNECT, &reconnect );
	mysql_options( db, MYSQL_OPT_PROTOCOL, (const char *)&protocol );

	if ( mysql_real_connect( db, dbhost.c_str(), dbuser.c_str(), dbpassword.c_str(), database.c_str(), 0, NULL, CLIENT_MULTI_STATEMENTS ) == NULL )
		error( std::string( "Unable to open mysql: " ) + mysql_error( db ) );

	dbs[std::this_thread::get_id()] = db;
}

////////////////////////////////////////

void threadStopBackend( void )
{
	std::unique_lock<std::mutex> lock( db_mutex );
	MYSQL *db = dbs[std::this_thread::get_id()];
	dbs.erase( std::this_thread::get_id() );
	lock.unlock();

	mysql_close( db );
	mysql_thread_end();
}

////////////////////////////////////////

std::vector<uint32_t> getIPAddresses( const uint8_t *hwaddr, bool avail )
{
	std::unique_lock<std::mutex> lock( db_mutex );
	MYSQL *db = dbs[std::this_thread::get_id()];
	lock.unlock();

	std::string query;
	if ( avail )
	{
		query = format (
			"SELECT ip_addr FROM dhcp_host "
				"WHERE ( mac_addr=x'{0,B16,f0,w2}' OR mac_addr=x'000000000000' ) "
				"AND ip_addr NOT IN ( SELECT ip_addr FROM dhcp_lease WHERE mac_addr <> x'{0,B16,f0,w2}' ) "
				"ORDER BY mac_addr DESC, dhcp_host.ip_addr ASC",
			as_hex<uint8_t>( hwaddr, 6 ) );
	}
	else
	{
		query = format (
			"SELECT ip_addr FROM dhcp_host "
				"WHERE mac_addr=x'{0,B16,f0,w2}' OR mac_addr=x'000000000000' "
				"ORDER BY mac_addr DESC, dhcp_host.ip_addr ASC",
			as_hex<uint8_t>( hwaddr, 6 ) );
	}

	if ( mysql_query( db, query.c_str() ) != 0 )
		error( format( "Error querying mysql: {0}", mysql_error( db ) ) );

	MYSQL_RES *result = mysql_store_result( db );
	auto freeres = make_guard( [=](){ mysql_free_result( result ); } );

	if ( result == NULL )
		error( format( "Error storing result from mysql: {0}", mysql_error( db ) ) );

	std::vector<uint32_t> ret;

	MYSQL_ROW row;
	while ( ( row = mysql_fetch_row( result ) ) )
	{
		if ( row != NULL && row[0] )
			ret.push_back( htonl( atoi( row[0] ) ) );
	}

	return ret;
}

////////////////////////////////////////

void getOptions( uint32_t ip, std::vector<std::string> &options )
{
	std::unique_lock<std::mutex> lock( db_mutex );
	MYSQL *db = dbs[std::this_thread::get_id()];
	lock.unlock();

	std::string query = format( "SELECT options FROM dhcp_options WHERE ( {0} >= ip_addr_from AND {0} <= ip_addr_to )", ntohl( ip ) );

	if ( mysql_query( db, query.c_str() ) != 0 )
		error( std::string( "Error querying mysql: " ) + mysql_error( db ) );

	MYSQL_RES *result = mysql_store_result( db );
	auto freeres = make_guard( [=](){ mysql_free_result( result ); } );

	if ( result == NULL )
		error( std::string( "Error storing result from mysql: " ) + mysql_error( db ) );

	MYSQL_ROW row;
	while ( ( row = mysql_fetch_row( result ) ) )
	{
		unsigned long *lengths = mysql_fetch_lengths( result );
		options.push_back( std::string( row[0], lengths[0] ) );
	}
}

////////////////////////////////////////

void addHost( uint32_t ip, const uint8_t *mac )
{
	std::unique_lock<std::mutex> lock( db_mutex );
	MYSQL *db = dbs[std::this_thread::get_id()];
	lock.unlock();

	std::string query = format(
		"INSERT INTO dhcp_host ( ip_addr, mac_addr )"
			"VALUES( {0}, x'{1,B16,f0,w2}' )",
		ntohl( ip ), as_hex<uint8_t>( mac, 6 ) );

	if ( mysql_query( db, query.c_str() ) != 0 )
		error( std::string( "Error querying mysql: " ) + mysql_error( db ) );
}

////////////////////////////////////////

void removeHost( uint32_t ip )
{
	std::unique_lock<std::mutex> lock( db_mutex );
	MYSQL *db = dbs[std::this_thread::get_id()];
	lock.unlock();

	std::string query = format( "DELETE FROM dhcp_host WHERE ip_addr = {0}", ntohl( ip ) );

	if ( mysql_query( db, query.c_str() ) != 0 )
		error( std::string( "Error querying mysql: " ) + mysql_error( db ) );
}

////////////////////////////////////////

void addOption( uint32_t ip1, uint32_t ip2, const std::string &opt )
{
	std::unique_lock<std::mutex> lock( db_mutex );
	MYSQL *db = dbs[std::this_thread::get_id()];
	lock.unlock();

	std::string query = format(
		"INSERT INTO dhcp_options ( ip_addr_from, ip_addr_to, options )"
			"VALUES( {0}, {1}, x'{2,B16,f0,w2}' )",
		ntohl( ip1 ), ntohl( ip2 ), as_hex<char>( opt ) );

	if ( mysql_query( db, query.c_str() ) != 0 )
		error( std::string( "Error querying mysql: " ) + mysql_error( db ) );
}

////////////////////////////////////////

void removeOption( uint32_t ip1, uint32_t ip2, const std::string &opt )
{
	std::unique_lock<std::mutex> lock( db_mutex );
	MYSQL *db = dbs[std::this_thread::get_id()];
	lock.unlock();

	std::string query = format( "DELETE FROM dhcp_options WHERE ip_addr_from={0} AND ip_addr_to={1} AND options=x'{2,B16,f0,w2}'",
		ntohl( ip1 ), ntohl( ip2 ), as_hex<char>( opt ) );

	if ( mysql_query( db, query.c_str() ) != 0 )
		error( std::string( "Error querying mysql: " ) + mysql_error( db ) );
}

////////////////////////////////////////

bool acquireLease( uint32_t ip, const uint8_t *hwaddr, uint32_t time )
{
	std::unique_lock<std::mutex> lock( db_mutex );
	MYSQL *db = dbs[std::this_thread::get_id()];
	lock.unlock();

	std::string query = format(
		"INSERT IGNORE INTO dhcp_lease ( ip_addr, mac_addr, expiration ) "
			"VALUES( {0}, x'{1,B16,f0,w2}', TIMESTAMPADD( SECOND, {2}, NOW() ) )",
		ntohl( ip ), as_hex<uint8_t>(hwaddr,6), time );

	if ( mysql_query( db, query.c_str() ) != 0 )
	{
		syslog( LOG_ERR, "Acquire lease: %s", mysql_error( db ) );
		return false;
	}

	query = format( "UPDATE dhcp_lease SET expiration=TIMESTAMPADD( SECOND, {2}, NOW() )"
			"WHERE ip_addr={0} AND mac_addr = x'{1,B16,f0,w2}'",
		ntohl( ip ), as_hex<uint8_t>(hwaddr,6), time );

	if ( mysql_affected_rows( db ) != 1 )
	{
		syslog( LOG_ERR, "Acquire lease failed: ip is already assigned" );
		return false;
	}

	return true;
}

////////////////////////////////////////

bool releaseLease( uint32_t ip, const uint8_t *hwaddr )
{
	std::unique_lock<std::mutex> lock( db_mutex );
	MYSQL *db = dbs[std::this_thread::get_id()];
	lock.unlock();

	std::string query = format(
		"DELETE FROM dhcp_lease "
			"WHERE ip_addr = {0} AND mac_addr = x'{1,B16,f0,w2}'",
		ntohl( ip ), as_hex<uint8_t>(hwaddr) );

	if ( mysql_query( db, query.c_str() ) != 0 )
		return false;

	if ( mysql_affected_rows( db ) < 1 )
		return false;

	return true;
}


////////////////////////////////////////

