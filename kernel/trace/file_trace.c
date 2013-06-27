/**
 * A file_trace tracer.
 *
 * Copyright (C) 2013 Mateusz Machalica <mateuszmachalica@gmail.com>
 **/

#include <linux/ftrace.h>
#include "trace.h"

#define CREATE_TRACE_POINTS
#include <trace/events/file_trace.h>

static bool file_trace_context_info;
static bool file_trace_enabled = false;

static void file_trace_start(struct trace_array *tr) {
	file_trace_context_info = (trace_flags & TRACE_ITER_CONTEXT_INFO);
	trace_flags &= ~TRACE_ITER_CONTEXT_INFO;
	file_trace_enabled = true;
}

static void file_trace_stop(struct trace_array *tr) {
	file_trace_enabled = false;
	if (file_trace_context_info)
		trace_flags |= TRACE_ITER_CONTEXT_INFO;
}

static void probe_open(pid_t pid, char *filename, int flags, int mode, long
		retval) {
	// FIXME
}

static void file_trace_register_tracepoints(void) {
	int ret;

	ret = register_trace_file_trace_open(probe_open);
	WARN_ON(ret);
}

static void file_trace_unregister_tracepoints(void) {
	unregister_trace_file_trace_open(probe_open);

	tracepoint_synchronize_unregister();
}

static int file_trace_init(struct trace_array *tr) {
	tracing_reset_online_cpus(tr);
	file_trace_register_tracepoints();
	file_trace_start(tr);
	return 0;
}

static void file_trace_reset(struct trace_array *tr) {
	file_trace_stop(tr);
	file_trace_unregister_tracepoints();
	tracing_reset_online_cpus(tr);
}

static void file_trace_print_header(struct seq_file *s) {
	seq_puts(s, "");
}

struct tracer file_tracer __read_mostly = {
	.name = "file_trace",
	.init = file_trace_init,
	.reset = file_trace_reset,
	.start = file_trace_start,
	.stop = file_trace_stop,
	.print_header = file_trace_print_header,
};
