/**
 * A file_trace tracer.
 *
 * Copyright (C) 2013 Mateusz Machalica <mateuszmachalica@gmail.com>
 **/

#include <linux/ftrace.h>
#include "trace.h"

static bool file_trace_enabled = false;

static void file_trace_start(struct trace_array *tr) {
	file_trace_enabled = true;
}

static void file_trace_stop(struct trace_array *tr) {
	file_trace_enabled = false;
}

static int file_trace_init(struct trace_array *tr) {
	tracing_reset_online_cpus(tr);
	file_trace_start(tr);
	return 0;
}

static void file_trace_reset(struct trace_array *tr) {
	file_trace_stop(tr);
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
