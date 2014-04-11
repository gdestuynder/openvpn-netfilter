/* 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING included with this
 * distribution); if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 * 
 * Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net> (defer/simple.c)
 * Copyright (C) 2014 Mozilla Corporation <gdestuynder@mozilla.com>
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <openvpn-plugin.h>

struct context {
	char *script_path;
};

static int
generic_deferred_handler(char *script_path, const char * envp[])
{
	int pid;
	char *argv[] = {script_path, 0};
	
	signal(SIGCHLD, SIG_IGN);
	pid = fork();

	if (pid < 0) {
		return OPENVPN_PLUGIN_FUNC_ERROR;
	}

	if (pid > 0) {
		return OPENVPN_PLUGIN_FUNC_DEFERRED;
	}
	
	execve(argv[0], &argv[0], (char *const*)envp);
	exit(127);
}

OPENVPN_EXPORT int
openvpn_plugin_func_v2(openvpn_plugin_handle_t handle, const int type, const char *argv[],
						const char *envp[], void *per_client_context,
						struct openvpn_plugin_string_list **return_list)
{
	struct context *ctx = (struct context *) handle;

	if (type == OPENVPN_PLUGIN_LEARN_ADDRESS) {
		return generic_deferred_handler(ctx->script_path, envp);
	} else {
		return OPENVPN_PLUGIN_FUNC_ERROR;
	}
}

OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v2(unsigned int *type_mask, const char *argv[], const char *envp[],
						struct openvpn_plugin_string_list **return_list)
{
	struct context *ctx;
	
	ctx = (struct context *) calloc(1, sizeof(struct context));

	if (argv[1]) {
		ctx->script_path = strdup(argv[1]);
	}
	*type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_LEARN_ADDRESS);

	return (openvpn_plugin_handle_t) ctx;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
	struct context *ctx = (struct context *) handle;

	free(ctx->script_path);
	free(ctx);
}
