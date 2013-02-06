
#include "packet_queue.h"
#include "packet.h"

////////////////////////////////////////

void packet_queue::queue( packet *p )
{
	std::unique_lock<std::mutex> lock( _mutex );
	_list.push_back( p );
	_condition.notify_all();
}

////////////////////////////////////////

packet *packet_queue::wait( void )
{
	std::unique_lock<std::mutex> lock( _mutex );
	while ( _list.empty() )
		_condition.wait( lock );
	
	packet *p = _list.front();
	_list.pop_front();
	return p;
}

////////////////////////////////////////

packet *packet_queue::alloc( void )
{
	std::unique_lock<std::mutex> lock( _emutex );

	packet *p = NULL;
	if ( !_empty.empty() )
	{
		p = _empty.front();
		_empty.pop_front();
	}

	if ( p == NULL )
		p = new packet;

	return p;
}

////////////////////////////////////////

void packet_queue::free( packet *p )
{
	std::unique_lock<std::mutex> lock( _emutex );
	_empty.push_back( p );
}

////////////////////////////////////////

