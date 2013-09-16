/* This file is part of Netsukuku
 * (c) Copyright 2005 Andrea Lo Pumo aka AlpT <alpt@freaknet.org>
 *
 * This source code is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This source code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * Please refer to the GNU Public License for more details.
 *
 * You should have received a copy of the GNU Public License along with
 * this source code; if not, write to:
 * Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef REHOOK_H
#define REHOOK_H

int rehook_mutex;	/* The can be only one rehook at the same time */

/*
 * REHOOK_PER_INSTANCE the is total number of rehooks allowed in
 * REHOOK_INSTANCE_TIME(level) seconds. After REHOOK_INSTANCE_TIME(level)
 * seconds have passed since the first rehook, REHOOK_WAIT_TIME(level) seconds
 * must be waited before rehooking again.
 * `level' is the level where the rehook is taking place.
 * REHOOK_WAIT_TIME is calculated in this way:
 * 	((8<<level) - (1<<level)) * 60
 */
#define REHOOK_PER_INSTANCE		8
#define REHOOK_INSTANCE_TIME(level)	(REHOOK_PER_INSTANCE*(level)*60)
#define REHOOK_WAIT_TIME(level)		(( (8<<(level)) - (1<<(level)) ) * 60)


time_t last_instance_rehook;		/* When the first rehook of the latest
					   instance occurred */
int total_rehooks;			/* Number of rehooks made in the current 
					   instance. 
					   It cannot be > REHOOK_PER_INSTANCE */



#define CHALLENGE_THRESHOLD	(1<<16)	/* When the gnode X, which must
					   rehook, has a gnode_count >= (1<<16) 
					   it sends a new challenge. */

/* `rk_gnode_ip' is the ip that will be used if we cannot rehook directly to 
 * any gnode: a new gnode is created with the ip equal to `rk_gnode_ip'. */
inet_prefix rk_gnode_ip;

/*  *  *  Functions declaration  *  *  */
void rehook_init(void);
void new_rehook(map_gnode *gnode, int gid, int level, int gnode_count);
int rehook(map_gnode *hook_gnode, int hook_level);

#endif /*REHOOK_H*/
