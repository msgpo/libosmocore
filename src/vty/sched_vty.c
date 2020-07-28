/*! \file sched_vty.c
 * Implementation to CPU / Threading / Scheduler properties from VTY configuration.
 */
/* (C) 2020 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPLv2+
 */

#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sched.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/tdef_vty.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/linuxlist.h>

/*! \addtogroup Tdef_VTY
 *
 * CPU Scheduling related VTY API.
 *
 * @{
 * \file sched_vty.c
 */

enum sched_vty_thread_id {
	SCHED_VTY_THREAD_SELF,
	SCHED_VTY_THREAD_ALL,
	SCHED_VTY_THREAD_ID,
	SCHED_VTY_THREAD_NAME,
	SCHED_VTY_THREAD_UNKNOWN,
};

struct cpu_affinity_it {
	struct llist_head entry;
	enum sched_vty_thread_id tid_type;
	char bufname[64];
	unsigned long mask;
	bool delay;
};

struct sched_vty_opts {
	void *tall_ctx;
	int sched_rr_prio;
	struct llist_head cpu_affinity_li;
	pthread_mutex_t cpu_affinity_li_mutex;
};


static struct sched_vty_opts *sched_vty_opts;

static struct cmd_node sched_node = {
	L_SCHED_NODE,
	"%s(config-sched)# ",
	1,
};


/*TODO: Add API to request apply affinity mask on a thread name. Fallback to "all". The cpu_addinity_li mist be protected by a mutex */
/*TODO: add vty tests */

static bool proc_tid_exists(pid_t tid)
{
	DIR *proc_dir;
	struct dirent *entry;
	char dirname[100];
	int tid_it;
	bool found = false;

	snprintf(dirname, sizeof(dirname), "/proc/%ld/task", (long int)getpid());
	proc_dir = opendir(dirname);
	if (!proc_dir)
		return false; /*FIXME; print error */

	while ((entry = readdir(proc_dir)))
	{
		if(entry->d_name[0] == '.')
			continue;
		tid_it = atoi(entry->d_name);
		if (tid_it == tid) {
			found = true;
			break;
		}
	}

	closedir(proc_dir);
	return found;
}

static bool proc_name_exists(const char *name, pid_t *res_pid)
{
	DIR *proc_dir;
	struct dirent *entry;
	char path[100];
	char buf[16];
	int tid_it;
	int fd;
	pid_t mypid = getpid();
	bool found = false;
	int rc;

	*res_pid = 0;

	snprintf(buf, sizeof(path), "/proc/%ld/task", (long int)mypid);
	proc_dir = opendir(path);
	if (!proc_dir)
		return false; /*FIXME; print error */

	while ((entry = readdir(proc_dir)))
	{
		if(entry->d_name[0] == '.')
			continue;

		tid_it = atoi(entry->d_name);
		snprintf(path, sizeof(path), "/proc/%ld/task/%ld/comm", (long int)mypid, (long int) tid_it);
		if ((fd = open(path, O_RDONLY)) == -1)
			continue;
		rc = read(fd, buf, sizeof(buf));
		if (rc >= 0) {
			buf[rc] = '\0';
			if (strcmp(name, buf) == 0) {
				*res_pid = tid_it;
				found = true;
			}
		}
		close(fd);

		if (found)
			break;
	}

	closedir(proc_dir);
	return found;
}

static enum sched_vty_thread_id procname2pid(pid_t *res_pid, const char *str, bool applynow)
{
	size_t i, len;
	char *end;
	bool is_pid = true;

	if (strcmp(str, "all") == 0) {
		*res_pid = 0;
		return SCHED_VTY_THREAD_ALL;
	}

	if (strcmp(str, "self") == 0) {
		*res_pid = 0;
		return SCHED_VTY_THREAD_SELF;
	}

	len = strlen(str);
	for (i = 0; i < len; i++) {
		if (!isdigit(str[i])) {
			is_pid = false;
			break;
		}
	}
	if (is_pid) {
		errno = 0;
		*res_pid = strtoul(str, &end, 0);
		if ((errno == ERANGE && *res_pid == ULONG_MAX) || (errno && !*res_pid) ||
		    str == end) {
			return SCHED_VTY_THREAD_UNKNOWN;
		}
		if (!applynow || proc_tid_exists(*res_pid))
			return SCHED_VTY_THREAD_ID;
		else
			return SCHED_VTY_THREAD_UNKNOWN;
	}

	if (len > 15) {
		/* Thread names only allow up to 15+1 null chars, see man pthread_setname_np */
		return SCHED_VTY_THREAD_UNKNOWN;
	}

	if (applynow) {
		if (proc_name_exists(str, res_pid))
			return SCHED_VTY_THREAD_NAME;
		else
			return SCHED_VTY_THREAD_UNKNOWN;
	} else  {
		/* assume a thread will be named after it */
		*res_pid = 0;
		return SCHED_VTY_THREAD_NAME;
	}
}

int my_sched_setaffinity(enum sched_vty_thread_id tid_type, pid_t pid, unsigned long mask)
{
	DIR *proc_dir;
	struct dirent *entry;
	char dirname[100];
	int tid_it;
	int rc = 0;
	unsigned long mask_tmp;
	cpu_set_t *cpuset;
	size_t cpuset_size;
	unsigned int cpu_i = 0;

	cpuset = CPU_ALLOC(64);
	cpuset_size = CPU_ALLOC_SIZE(64);
	CPU_ZERO_S(cpuset_size, cpuset);
	mask_tmp = mask;
	while (mask_tmp) {
		if (mask_tmp & 0x01)
			CPU_SET_S(cpu_i, cpuset_size, cpuset);
		mask_tmp >>= 1;
		cpu_i++;
	}

	if (tid_type != SCHED_VTY_THREAD_ALL) {
		LOGP(DLGLOBAL, LOGL_NOTICE, "Setting CPU affinity mask for tid %lu to: 0x%lx\n",
		     (unsigned long) pid, mask);

		rc = sched_setaffinity(pid, sizeof(cpu_set_t), cpuset);
		CPU_FREE(cpuset);
		return rc;
	}

	snprintf(dirname, sizeof(dirname), "/proc/%ld/task", (long int)getpid());
	proc_dir = opendir(dirname);
	if (!proc_dir) {
		CPU_FREE(cpuset);
		return -EINVAL; /*FIXME; print error */
	}

	while ((entry = readdir(proc_dir)))
	{
		if(entry->d_name[0] == '.')
			continue;
		tid_it = atoi(entry->d_name);
		LOGP(DLGLOBAL, LOGL_NOTICE, "Setting CPU affinity mask for tid %lu to: 0x%lx\n",
		     (unsigned long) tid_it, mask);

		rc = sched_setaffinity(tid_it, sizeof(cpu_set_t), cpuset);
		if (rc == -1)
			break;
	}

	closedir(proc_dir);
	CPU_FREE(cpuset);
	return rc;

}

DEFUN(cfg_sched_cpu_affinity, cfg_sched_cpu_affinity_cmd,
	"cpu-affinity (self|all|<0-4294967295>|THREADNAME) <0x00-0xffffffffffffffff> [delay]", /* Allow up to 64 CPUs */
	"Set Target thread to apply the CPU affinty mask\n"
	"Set CPU affinity mask of the thread\n"
	"CPU affinity mask\n"
	"If set, delay applying the affinity mask now and let the app handle it at a later point\n")
{
	unsigned long mask;
	const char* str_who = argv[0];
	const char *str_mask = argv[1];
	bool applynow = (argc != 3);
	char *end;
	int rc;
	pid_t pid;
	enum sched_vty_thread_id tid_type;
	struct cpu_affinity_it *it, *it_next;

	tid_type = procname2pid(&pid, str_who, applynow);
	if (tid_type == SCHED_VTY_THREAD_UNKNOWN) {
		vty_out(vty, "%% Failed parsing target thread %s%s",
		        str_who, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (tid_type == SCHED_VTY_THREAD_ID && !applynow)  {
		vty_out(vty, "%% It makes no sense to delay applying cpu-affinity on tid %lu%s",
			(unsigned long)pid, VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (tid_type == SCHED_VTY_THREAD_ALL && !applynow)  {
		vty_out(vty, "%% It makes no sense to delay applying cpu-affinity on all threads%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	errno = 0;
	mask = strtoul(str_mask, &end, 0);
	if ((errno == ERANGE && mask == ULONG_MAX) || (errno && !mask) ||
	    str_mask == end) {
		vty_out(vty, "%% Failed parsing CPU Affinity Mask %s%s",
			str_mask, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (applynow) {
		rc = my_sched_setaffinity(tid_type, pid, mask);
		if (rc == -1) {
			vty_out(vty, "%% Failed setting sched CPU Affinity Mask 0x%lx: %s%s",
				mask, strerror(errno), VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	/* Keep history of cmds applied to be able to rewrite config. If PID was passed
	   directly it makes no sense to store it since PIDs are temporary */
	if (tid_type == SCHED_VTY_THREAD_SELF ||
	    tid_type == SCHED_VTY_THREAD_ALL ||
	    tid_type == SCHED_VTY_THREAD_NAME) {
		pthread_mutex_lock(&sched_vty_opts->cpu_affinity_li_mutex);

		/* Drop previous entries matching, since they will be overwritten */
		llist_for_each_entry_safe(it, it_next, &sched_vty_opts->cpu_affinity_li, entry) {
			if (strcmp(it->bufname, str_who) == 0) {
				llist_del(&it->entry);
				talloc_free(it);
				break;
			}
		}
		it = talloc_zero(sched_vty_opts->tall_ctx, struct cpu_affinity_it);
		OSMO_STRLCPY_ARRAY(it->bufname, str_who);
		it->tid_type = tid_type;
		it->mask = mask;
		it->delay = !applynow;
		llist_add_tail(&it->entry, &sched_vty_opts->cpu_affinity_li);

		pthread_mutex_unlock(&sched_vty_opts->cpu_affinity_li_mutex);
	}

	return CMD_SUCCESS;
}

static int set_sched_rr(unsigned int prio)
{
	struct sched_param param;
	int rc;
	memset(&param, 0, sizeof(param));
	param.sched_priority = prio;
	LOGP(DLGLOBAL, LOGL_NOTICE, "Setting SCHED_RR priority %d\n", param.sched_priority);
	rc = sched_setscheduler(getpid(), SCHED_RR, &param);
	if (rc == -1) {
		LOGP(DLGLOBAL, LOGL_FATAL, "Setting SCHED_RR priority %d failed: %s\n",
		     param.sched_priority, strerror(errno));
		return -1;
	}
	return 0;
}

DEFUN(cfg_sched_policy, cfg_sched_policy_cmd,
	"policy rr <1-32>",
	"Set the scheduling policy to use for the process\n"
	"Use the SCHED_RR real-time scheduling algorithm\n"
	"Use the SCHED_RR real-time priority\n"
	"Real time priority\n")
{
	sched_vty_opts->sched_rr_prio = atoi(argv[0]);

	if (set_sched_rr(sched_vty_opts->sched_rr_prio) < 0) {
		vty_out(vty, "%% Failed setting SCHED_RR priority %d%s",
			sched_vty_opts->sched_rr_prio, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_sched,
      cfg_sched_cmd,
      "sched", "Configure CPU Scheduler related settings")
{
	vty->index = NULL;
	vty->node = L_SCHED_NODE;

	return CMD_SUCCESS;
}

static int config_write_sched(struct vty *vty)
{
	struct cpu_affinity_it *it;

	/* Only add the node if there's something to write under it */
	if (sched_vty_opts->sched_rr_prio || !llist_empty(&sched_vty_opts->cpu_affinity_li))
		vty_out(vty, "sched%s", VTY_NEWLINE);

	if (sched_vty_opts->sched_rr_prio)
		vty_out(vty, " policy rr %d%s", sched_vty_opts->sched_rr_prio, VTY_NEWLINE);

	llist_for_each_entry(it, &sched_vty_opts->cpu_affinity_li, entry) {
		vty_out(vty, " cpu-affinity %s 0x%lx%s%s", it->bufname, it->mask,
			it->delay ? " delay" : "", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

/*! Initialize sched VTY nodes
 * \param[in] vty  VTY context for vty_out() of error messages.
 * \param[in] tdefs  Array of timer definitions to look up T timer.
 * \param[in] T_str  Argument string. It is not validated, expected to be checked by VTY input.
 * \return 0 on success, non-zero on error.
 */
int osmo_sched_vty_init(void *tall_ctx)
{
	OSMO_ASSERT(!sched_vty_opts); /* assert only called once */

	sched_vty_opts = talloc_zero(tall_ctx, struct sched_vty_opts);
	sched_vty_opts->tall_ctx = tall_ctx;
	INIT_LLIST_HEAD(&sched_vty_opts->cpu_affinity_li);
	pthread_mutex_init(&sched_vty_opts->cpu_affinity_li_mutex, NULL);

	install_element(CONFIG_NODE, &cfg_sched_cmd);
	install_node(&sched_node, config_write_sched);

	install_element(L_SCHED_NODE, &cfg_sched_policy_cmd);
	install_element(L_SCHED_NODE, &cfg_sched_cpu_affinity_cmd);
	return 0;
}

/*! Apply cpu-affinity on calling thread based on VTY configuration
 * \return 0 on success, non-zero on error.
 */
int osmo_sched_vty_apply_localthread(void)
{
	struct cpu_affinity_it *it;
	char name[16];
	bool has_name = false;
	bool mask_found = false;
	unsigned long mask;
	int rc;

	/* Assert subsystem was inited and structs are preset */
	OSMO_ASSERT(sched_vty_opts);

	if (pthread_getname_np(pthread_self(), name, sizeof(name)) == 0)
		has_name = true;

	/* Get latest matching mask for the thread */
	pthread_mutex_lock(&sched_vty_opts->cpu_affinity_li_mutex);
	llist_for_each_entry(it, &sched_vty_opts->cpu_affinity_li, entry) {
		switch (it->tid_type) {
		case SCHED_VTY_THREAD_SELF:
			continue; /* self to the VTY thread, not us */
		case SCHED_VTY_THREAD_ALL:
			mask_found = true;
			mask = it->mask;
			break;
		case SCHED_VTY_THREAD_NAME:
			if (!has_name)
				continue;
			if (strcmp(name, it->bufname) != 0)
				continue;
			mask_found = true;
			mask = it->mask;
			break;
		default:
			OSMO_ASSERT(0);
		}
	}
	pthread_mutex_unlock(&sched_vty_opts->cpu_affinity_li_mutex);

	if (!mask_found)
		return 0;

	rc = my_sched_setaffinity(SCHED_VTY_THREAD_SELF, 0, mask);
	if (rc == -1)
		LOGP(DLGLOBAL, LOGL_FATAL, "Setting cpu-affinity mask 0x%lx failed: %s\n",
		     mask, strerror(errno));
	return rc;
}

/*! @} */
