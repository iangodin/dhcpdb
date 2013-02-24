
CMAKE_MINIMUM_REQUIRED( VERSION 2.6 )

SET( CMAKE_CXX_FLAGS "-std=c++11" )
LINK_DIRECTORIES( /usr/lib64/mysql )

ADD_EXECUTABLE( dhcpdb
	format.cpp
	lookup.cpp
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

INSTALL( TARGETS dhcpdb RUNTIME DESTINATION bin )
INSTALL( FILES sample.conf DESTINATION /etc RENAME dhcpdb.conf )
INSTALL( PROGRAMS dhcpdb.init DESTINATION /etc/init.d RENAME dhcpdb )
INSTALL( FILES dhcpdb.default DESTINATION /etc/sysconfig RENAME dhcpdb )
INSTALL( FILES dhcp-options.txt DESTINATION /usr/share/dhcpdb )

