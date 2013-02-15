
CMAKE_MINIMUM_REQUIRED( VERSION 2.6 )

SET( CMAKE_CXX_FLAGS "-std=c++11" )
LINK_DIRECTORIES( /usr/lib64/mysql )

ADD_EXECUTABLE( dhcpdb
	format.cpp
	strutils.cpp
	option.cpp
	error.cpp
	backend.cpp
	config.cpp
	packet.cpp
	udp_socket.cpp
	packet_queue.cpp
	server.cpp
	handler.cpp
	daemon.cpp
	main.cpp
)

TARGET_LINK_LIBRARIES( dhcpdb
	mysqlclient
)

