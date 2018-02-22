//  Distributed Key Generator
//  Copyright 2012 Aniket Kate <aniket@mpi-sws.org>, Andy Huang <y226huan@uwaterloo.ca>, Ian Goldberg <iang@uwaterloo.ca>
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of version 3 of the GNU General Public License as
//  published by the Free Software Foundation.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  There is a copy of the GNU General Public License in the COPYING file
//  packaged with this plugin; if you cannot find it, write to the Free
//  Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
//  MA 02110-1301 USA



#include "io.h"
#include "exceptions.h"



void hash_msg(G1& elt, string msg, const Pairing& e)
{
    unsigned char hashbuf[20];
    //unsigned char idbuf[2];
    //idbuf[0] = (id >> 8) & 0xff;
    //idbuf[1] = (id) & 0xff;
    gcry_md_hash_buffer(GCRY_MD_SHA1, hashbuf, msg.data(), 2);
    elt = G1(e, (void*)hashbuf, 20);
}

