/* This file is part of Netsukuku
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
 *
 */
#ifndef CONSOLE_H
#define CONSOLE_H


#define CONSOLE_SOCKET_PATH 	"/tmp/ntk-console"
#define CONSOLE_VERSION_MAJOR	0
#define CONSOLE_VERSION_MINOR 	3
#define CONSOLE_ARGV_LENGTH 	250
#define CONSOLE_BUFFER_LENGTH 	250

#ifndef TRUE
#define FALSE               0
#define TRUE                1
#endif


typedef enum {
    COMMAND_HELP = 0x100,
    COMMAND_UPTIME,
    COMMAND_KILL,
    COMMAND_VERSION,
    COMMAND_INETCONN,
    COMMAND_CURIFS,
    COMMAND_CURIFSCT,
    COMMAND_CURQSPNID,
    COMMAND_CURIP,
    COMMAND_CURNODE,
    COMMAND_IFS,
    COMMAND_IFSCT,
    COMMAND_QUIT,
    COMMAND_CONSUPTIME,
} command_t;


#pragma pack(1)
typedef struct {
	command_t command;
	char* argv[CONSOLE_ARGV_LENGTH];
} cmd_packet_t;
#pragma pack(0)


#endif /* CONSOLE_H */
