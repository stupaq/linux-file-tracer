/**
 * A file_trace tracer events.
 *
 * Copyright (C) 2013 Mateusz Machalica <mateuszmachalica@gmail.com>
 **/

#undef TRACE_SYSTEM
#define TRACE_SYSTEM file_trace

#if !defined(_TRACE_EVENTS_FILE_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_EVENTS_FILE_TRACE_H

#include <linux/tracepoint.h>

#include <linux/types.h>
#include <linux/err.h>

#define succ_or_err(val) \
	__print_symbolic(!IS_ERR_VALUE(val), {true, "SUCCESS"}, {false, "ERR"})
#define res_or_code(val) \
	(val < 0 ? -val : val)

TRACE_EVENT(file_trace_open,

	TP_PROTO(const char *filename, int flags, int mode, long retval),

	TP_ARGS(filename, flags, mode, retval),

	TP_STRUCT__entry(
		__field(	pid_t,		pid		)
		__string(	path,		filename	)
		__field(	int,		flags		)
		__field(	int,		mode		)
		__field(	long,		retval		)
	),

	TP_fast_assign(
		__entry->pid = task_pid_nr(current);
		__assign_str(path, filename);
		__entry->flags = flags;
		__entry->mode = mode;
		__entry->retval = retval;
	),

	TP_printk("%d OPEN %s %#x %#o %s %ld", __entry->pid, __get_str(path),
			__entry->flags, __entry->mode,
			succ_or_err(__entry->retval),
			res_or_code(__entry->retval)));

TRACE_EVENT(file_trace_close_ok,

	TP_PROTO(long fd),

	TP_ARGS(fd),

	TP_STRUCT__entry(
		__field(	pid_t,		pid		)
		__field(	long,		fd		)
	),

	TP_fast_assign(
		__entry->pid = task_pid_nr(current);
		__entry->fd = fd;
	),

	TP_printk("%d CLOSE %ld SUCCESS", __entry->pid, __entry->fd)
);

TRACE_EVENT(file_trace_close_bad,

	TP_PROTO(unsigned int fd, int retval),

	TP_ARGS(fd, retval),

	TP_STRUCT__entry(
		__field(	pid_t,		pid		)
		__field(	unsigned int,	fd		)
		__field(	int,		retval		)
	),

	TP_fast_assign(
		__entry->pid = task_pid_nr(current);
		__entry->fd = fd;
		__entry->retval = retval;
	),

	TP_printk("%d CLOSE %u ERR %d", __entry->pid, __entry->fd,
		res_or_code(__entry->retval))
);



TRACE_EVENT(file_trace_lseek,

	TP_PROTO(unsigned int fd, loff_t offset, unsigned int origin, int
		retval),

	TP_ARGS(fd, offset, origin, retval),

	TP_STRUCT__entry(
		__field(	pid_t,		pid		)
		__field(	unsigned int,	fd		)
		__field(	loff_t,		offset		)
		__field(	unsigned int,	origin		)
		__field(	int,		retval		)
	),

	TP_fast_assign(
		__entry->pid = task_pid_nr(current);
		__entry->fd = fd;
		__entry->offset = offset;
		__entry->origin = origin;
		__entry->retval = retval;
	),

	TP_printk("%d LSEEK %u %lld %d %s %d", __entry->pid, __entry->fd,
			__entry->offset, __entry->origin,
			succ_or_err(__entry->retval),
			res_or_code(__entry->retval))
);

#endif /* _TRACE_EVENTS_FILE_TRACE_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
