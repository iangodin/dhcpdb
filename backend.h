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

#pragma once

#include <stdint.h>
#include <vector>
#include <string>

#include "config.h"

////////////////////////////////////////

// Called once for each thread.
void threadStartBackend( void );
void threadStopBackend( void );

////////////////////////////////////////

// Get IP addresses for the given MAC address.
std::vector<uint32_t> getIPAddresses( const uint8_t *mac, bool avail = false );

// Get the DHCP options for the given IP.
void getOptions( uint32_t ip, std::vector<std::string> &options );

////////////////////////////////////////

void addHost( uint32_t ip, const uint8_t *mac );
void addOption( uint32_t ip1, uint32_t ip2, const std::string &option );

////////////////////////////////////////

// Acquire the lease for the given IP.
// You musst acquire an offer first.
bool acquireLease( uint32_t ip, const uint8_t *mac, uint32_t time );

// Release the lease with the given IP and MAC address.
bool releaseLease( uint32_t ip, const uint8_t *mac );

////////////////////////////////////////

