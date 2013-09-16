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

#ifndef CONF_H
#define CONF_H

#define CONF_MAX_LINES		500	/* Max number of option lines */

#define CONF_GET_VALUE(opt)		(getenv(config_str[(opt)]))
#define CONF_GET_INT_VALUE(opt, n)					\
({									\
	char *_val;							\
	_val=CONF_GET_VALUE((opt));					\
	if(_val)							\
		(n)=atoi(_val);						\
})
#define CONF_GET_STRN_VALUE(opt, str, maxbytes)				\
({									\
	char *_val;							\
	_val=CONF_GET_VALUE((opt));					\
 	if(_val)							\
 		*(str)=xstrndup(_val, (maxbytes));			\
})


/* 
 * The allowed options in the configuration file
 */
enum config_options
{
	CONF_NTK_INT_MAP_FILE,
	CONF_NTK_BNODE_MAP_FILE,
	CONF_NTK_EXT_MAP_FILE,

	CONF_ANDNA_HNAMES_FILE,
	CONF_SNSD_NODES_FILE,
	CONF_ANDNA_CACHE_FILE,
	CONF_ANDNA_LCLKEY_FILE,
	CONF_ANDNA_LCL_FILE,
	CONF_ANDNA_RHC_FILE,
	CONF_ANDNA_COUNTER_C_FILE,

	CONF_NTK_PID_FILE,
	CONF_NTK_MAX_CONNECTIONS,
	CONF_NTK_MAX_ACCEPTS_PER_HOST,
	CONF_NTK_MAX_ACCEPTS_PER_HOST_TIME,

	CONF_DISABLE_ANDNA,
	CONF_DISABLE_RESOLVCONF,
	
	CONF_NTK_RESTRICTED_MODE,
	CONF_NTK_RESTRICTED_CLASS,
	CONF_NTK_INTERNET_CONNECTION,
	CONF_NTK_INTERNET_GW,
	CONF_NTK_INTERNET_UPLOAD,
	CONF_NTK_INTERNET_DOWNLOAD,
	CONF_NTK_INTERNET_PING_HOSTS,
	CONF_SHARE_INTERNET,
	CONF_SHAPE_INTERNET,
	CONF_USE_SHARED_INET,
	CONF_NTK_IP_MASQ_SCRIPT,
	CONF_NTK_TC_SHAPER_SCRIPT,
};

const static char config_str[][30]=
{
	{ "ntk_int_map_file" },
	{ "ntk_bnode_map_file" },
	{ "ntk_ext_map_file" },
	
	{ "andna_hnames_file" },
	{ "snsd_nodes_file" },
	{ "andna_cache_file" },
	{ "andna_lclkey_file" },
	{ "andna_lcl_file" },
	{ "andna_rhc_file" },
	{ "andna_counter_c_file" },

	{ "pid_file" },
	{ "ntk_max_connections" },
	{ "ntk_max_accepts_per_host" },
	{ "max_accepts_per_host_time" },

	{ "disable_andna" },
	{ "disable_resolvconf" },
	{ "ntk_restricted_mode" },
	{ "ntk_restricted_class" },
	{ "internet_connection" },
	{ "internet_gateway" },
	{ "internet_upload_rate" },
	{ "internet_download_rate" },
	{ "internet_ping_hosts" },
	{ "share_internet" },
	{ "shape_internet" },
	{ "use_shared_internet" },
	{ "ip_masquerade_script" },
	{ "tc_shaper_script" },
	{ 0 },
};


void clear_config_env(void);
int load_config_file(char *file);

#endif /*CONF_H*/
