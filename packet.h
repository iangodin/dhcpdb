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

#include <stdint.h>
#include <iostream>

// BOOTP op codes
enum BootOp
{
	BOOT_REQUEST = 1,
	BOOT_REPLY = 2
};

// DHCP message types
enum MsgType
{
	DHCP_DISCOVER = 1,
	DHCP_OFFER = 2,
	DHCP_REQUEST = 3,
	DHCP_DECLINE = 4,
	DHCP_ACK = 5,
	DHCP_NAK = 6,
	DHCP_RELEASE = 7,
	DHCP_INFORM = 8,
	DHCP_LEASEQUERY = 10,
	DHCP_LEASEUNASSIGNED = 11,
	DHCP_LEASEUNKNOWN = 12,

	DHCP_UNKNOWN = 255
};

// DHCP options
enum Option
{
	DOP_PADDING = 0,
	DOP_SUBNET_MASK = 1,
	DOP_TIME_OFFSET = 2,
	DOP_ROUTER = 3,
	DOP_TIME_SERVER = 4,
	DOP_NAME_SERVER = 5,
	DOP_DOMAIN_NAME_SERVER = 6,
	DOP_LOG_SERVER = 7,
	DOP_COOKIE_SERVER = 8,
	DOP_LPR_SERVER = 9,
	DOP_IMPRESS_SERVER = 10,
	DOP_RESOURCE_LOC_SERVER = 11,
	DOP_HOSTNAME = 12,
	DOP_BOOTFILESIZE = 13,
	DOP_MERIT_DUMP = 14,
	DOP_DOMAIN_NAME = 15,
	DOP_SWAP_SERVER = 16,
	DOP_ROOT_PATH = 17,
	DOP_EXTENSIONS_PATH = 18,
	DOP_IP_FORWARDING = 19,
	DOP_NONLOCAL_SOURCE_ROUTING = 20,
	DOP_POLICY_FILTER = 21,
	DOP_MAXIMUM_DATAGRAM_REASSEMBLY_SIZE = 22,
	DOP_DEFAULT_IP_TTL = 23,
	DOP_PATH_MTU_AGING_TIMEOUT = 24,
	DOP_PATH_MTU_PLATEAU_TABLE = 25,
	DOP_INTERFACE_MTU = 26,
	DOP_ALL_SUBNETS_ARE_LOCAL = 27,
	DOP_BROADCAST_ADDRESS = 28,
	DOP_PERFORM_MASK_DISCOVERY = 29,
	DOP_MASK_SUPPLIER = 30,
	DOP_PERFORM_ROUTER_DISCOVERY = 31,
	DOP_ROUTER_SOLICITATION_ADDRESS = 32,
	DOP_STATIC_ROUTE = 33,
	DOP_TRAILER_ENCAPSULATION = 34,
	DOP_ARP_CACHE_TIMEOUT = 35,
	DOP_ETHERNET_ENCAPSULATION = 36,
	DOP_TCP_DEFAULT_TTL = 37,
	DOP_TCP_KEEPALIVE_INTERVAL = 38,
	DOP_TCP_KEEPALIVE_GARBAGE = 39,
	DOP_NETINFO_SERVICE_DOMAIN = 40,
	DOP_NETINFO_SERVERS = 41,
	DOP_NTP_SERVERS = 42,
	DOP_VENDOR_SPECIFIC_INFORMATION = 43,
	DOP_NETBIOS_OVER_TCPIP_NAME_SERVER = 44,
	DOP_NETBIOS_OVER_TCPIP_DATAGRAM_DISTRIBUTION_SERVER = 45,
	DOP_NETBIOS_OVER_TCPIP_NODETYPE = 46,
	DOP_NETBIOS_OVER_TCPIP_SCOPE = 47,
	DOP_XWINDOW_SYSTEM_FONTSERVER = 48,
	DOP_XWINDOW_SYSTEM_DISPLAY_MANAGER = 49,
	DOP_REQUESTED_IP_ADDRESS = 50,
	DOP_IP_ADDRESS_LEASETIME = 51,
	DOP_OPTION_OVERLOAD = 52,
	DOP_DHCP_MESSAGE_TYPE = 53,
	DOP_SERVER_IDENTIFIER = 54,
	DOP_PARAMETER_REQUEST_LIST = 55,
	DOP_MESSAGE = 56,
	DOP_MAXIMUM_DHCP_MESSAGE_SIZE = 57,
	DOP_RENEWAL_TIMEVALUE = 58,
	DOP_REBINDING_TIMEVALUE = 59,
	DOP_VENDOR_CLASS_IDENTIFIER = 60,
	DOP_CLIENT_IDENTIFIER = 61,
	DOP_NETINFO_SERVICEPLUS_DOMAIN = 64,
	DOP_NETINFO_SERVICEPLUS_SERVERS = 65,
	DOP_TFTP_SERVERNAME = 66,
	DOP_BOOT_FILENAME = 67,
	DOP_MOBILE_IP_HOME_AGENT = 68,
	DOP_SMTP_SERVER = 69,
	DOP_POP3_SERVER = 70,
	DOP_NNTP_SERVER = 71,
	DOP_DEFAULT_WWW_SERVER = 72,
	DOP_DEFAULT_FINGER_SERVER = 73,
	DOP_DEFAULT_IRC_SERVER = 74,
	DOP_STREET_TALK_SERVER = 75,
	DOP_STDA_SERVER = 76,
	DOP_CLIENT_SYSTEM_ARCH = 93,
	DOP_NETWORK_DEVICE_INTERFACE = 94,
	DOP_UNIQUE_CLIENT_ID = 97,
	DOP_END_OPTION = 255
};

// Hardware address types
enum HWAddr
{
	HWADDR_ETHER = 1,
	HWADDR_IEEE802 = 6,
	HWADDR_FDDI = 8
};


#pragma pack( push, 1 )
struct packet
{
	// DHCP packet 
	uint8_t  op, htype, hlen, hops;
	uint32_t xid;
	uint16_t secs, flags;
	uint32_t ciaddr, yiaddr, siaddr, giaddr;
	uint8_t chaddr[16];
	char sname[64];
	char file[128];
	uint8_t options[312];
};
#pragma pack( pop )

std::ostream &operator<<( std::ostream &out, const packet *p );
