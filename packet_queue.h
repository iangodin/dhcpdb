
#pragma once

#include <list>
#include <mutex>
#include <condition_variable>

struct packet;

////////////////////////////////////////

class packet_queue
{
public:
	void queue( packet *p );
	packet *wait( void );

	packet *alloc( void );
	void free( packet *p );

private:
	std::mutex _mutex;
	std::condition_variable _condition;
	std::list<packet *> _list;

	std::mutex _emutex;
	std::list<packet *> _empty;
};

////////////////////////////////////////

