//
// Copyright (c) 2013 Ian Godin
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
#include <syslog.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

////////////////////////////////////////

namespace
{

// Get the maximum number of files and close all files
void closeAllFiles( void )
{
	struct rlimit rl;
	if ( getrlimit( RLIMIT_NOFILE, &rl ) < 0 )
	{
		syslog( LOG_ERR, "Error getting maximum number of files" );
		exit( 1 );
	}
	
	if ( rl.rlim_max == RLIM_INFINITY )
		rl.rlim_max = 1024;

	for ( size_t i = 0; i < rl.rlim_max; ++i )
		::close( i );

	// Reopen stdin, stdout, and stderr as /dev/null
	int fd0 = ::open( "/dev/null", O_RDWR );
	int fd1 = ::dup( fd0 );
	int fd2 = ::dup( fd0 );

	// Check the file description for stdin, stdout, and stderr
	if ( fd0 != 0 || fd1 != 1 || fd2 != 2 )
	{
		::syslog( LOG_ERR, "unexpected file descriptor %d %d %d", fd0, fd1, fd2 );
		::exit( 1 );
	}
}

////////////////////////////////////////

// Fork the process and have the parent exit
void forkAndExit( void )
{
	int pid = ::fork();
	if ( pid < 0 )
	{
		::syslog( LOG_ERR, "Forking failed" );
		::exit( 1 );
	}
	
	if ( pid != 0 )
		::exit( 0 );
}

}

////////////////////////////////////////

void daemonize( const char *name, bool fg )
{
	// Clear the umask
	umask( 0 );

	if ( !fg )
	{
		// Close all files
		closeAllFiles();

		// Fork to guarantee we are not a process leader.
		forkAndExit();

		// Create a new session.
		setsid();

		// Fork one more time, to avoid ever acquiring a controlling TTY.
		forkAndExit();
	}

	// Reopen syslog (closeAllFiles probably closed it)
	if ( fg )
		openlog( name, LOG_CONS | LOG_PERROR | LOG_PID, LOG_DAEMON );
	else
		openlog( name, LOG_PERROR | LOG_PID, LOG_DAEMON );

	// Change to the root dir as to not prevent unmounts of filesystems
	if ( chdir( "/" ) < 0 )
	{
		syslog( LOG_ERR, "Can't change directory to /" );
		exit( 1 );
	}
}

////////////////////////////////////////

