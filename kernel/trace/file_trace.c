/**
 * A file_trace tracer.
 *
 * Copyright (C) 2013 Mateusz Machalica <mateuszmachalica@gmail.com>
 **/

#include <trace/file_trace.h>
#include <linux/ftrace.h>
#include "trace.h"

static struct trace_array *file_tracer = NULL;

/* Trace handlers */
void file_trace_open(const char __user *filename, int flags, int mode,
		long retval) {
	struct ftrace_event_call *call = &event_boot_call;
        struct ring_buffer_event *event;
        struct ring_buffer *buffer;
        struct trace_boot_open *entry;
	char *tmp;

	if (!file_tracer)
		return;
	tmp = getname(filename);
	if (IS_ERR(tmp))
		return;
	event = trace_buffer_lock_reserve(file_tracer->buffer, TRACE_FILE_OPEN,
			sizeof(*entry), 0, 0);
	if (!event)
		return;
	entry = ring_buffer_event_data(event);
	entry->flags;
	entry->mode;
	entry->retval;
	entry->filename = tmp;
	if (!filter_check_discard(call, entry, buffer, event))
		trace_buffer_unlock_commit(buffer, event, 0, 0);
}

void file_trace_close(unsigned int fd, int retval) {
	if (!file_tracer)
		return;
	// TODO
}

void probe_lseek(unsigned int fd, loff_t offset, int origin, int retval) {
	if (!file_tracer)
		return;
	// TODO
}

/* Tracer instrumentation */
static void file_trace_start(struct trace_array *tr) {
	file_tracer = tr;
}

static void file_trace_stop(struct trace_array *tr) {
	file_tracer = NULL;
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

/* Per-event printfs */
static int print_line_open(struct trace_iterator *iter) {
	struct file_trace_open *field;
	const char *format;
	int ret;

	BUG_ON(NULL == field->filename);
	trace_assign_type(field, iter->ent);
	format = "%d OPEN %s %#x %#o SUCCESS %d\n";
	if (IS_ERR_VALUE(field->retval)) {
		format = "%d OPEN %s %#x %#o ERR %d\n";
		field->retval *= -1;
	}
	ret = trace_seq_printf(iter->seq, format, field->pid, field->filename,
			field->flags, field->mode, field->retval);
	putname(field->filename);
	field->filename = NULL;
	return ret;
}

static int print_line_close(struct trace_iterator *iter) {
	struct file_trace_close *field;
	const char *format;
	trace_assign_type(field, ent);
	if (IS_ERR_VALUE(field->retval))
		return trace_seq_printf(seq, "%d CLOSE %d ERR %d\n"
				field->pid, field->fd, field->retval);
	else
		return trace_seq_printf(seq, "%d CLOSE %d SUCCESS\n",
				field->pid, field->fd);
}

static int print_line_read(struct trace_iterator *iter) {
	struct file_trace_read *field;
	const char *format;
	trace_assign_type(field, ent);
	format = "%d READ %d %d SUCCESS %d\n";
	if (IS_ERR_VALUE(field->retval)) {
		format = "%d READ %d %d ERR %d\n";
		field->retval *= -1;
	}
	return trace_seq_printf(seq, format, field->pid, field->fd,
			field->count, field->processed);
}

static int print_line_write(struct trace_iterator *iter) {
	struct file_trace_write *field;
	const char *format;
	trace_assign_type(field, ent);
	format = "%d WRITE %d %d SUCCESS %d\n";
	if (IS_ERR_VALUE(field->retval)) {
		format = "%d WRITE %d %d ERR %d\n";
		field->retval *= -1;
	}
	return trace_seq_printf(seq, format, field->pid, field->fd,
			field->count, field->processed);
}

static int print_line_rdata(struct trace_iterator *iter) {
	struct file_trace_rdata *field;
	const char *format;
	trace_assign_type(field, ent);
	if (field->length) {
		// TODO
	} else return trace_seq_printf(seq, "READ_DATA_FAULT\n");
}

static int print_line_wdata(struct trace_iterator *iter) {
	struct file_trace_wdata *field;
	const char *format;
	trace_assign_type(field, ent);
	if (field->length) {
		// TODO
	} else return trace_seq_printf(seq, "WRITE_DATA_FAULT\n");
}

static int print_line_lseek(struct trace_iterator *iter) {
	struct file_trace_lseek *field;
	const char *format;
	trace_assign_type(field, ent);
	format = "%d LSEEK %d %d %d SUCCESS %d\n";
	if (IS_ERR_VALUE(field->retval)) {
		format = "%d LSEEK %d %d %d ERR %d\n";
		field->retval *= -1;
	}
	return trace_seq_printf(seq, format, field->pid, field->fd,
			field->offset, field->origin, field->retval);
}

/* Printf dispatcher */
static enum print_line_t file_trace_print_line(struct trace_iterator *iter) {
	int ret = 1;

	switch (iter->ent) {
	case TRACE_FILE_OPEN:
		ret = print_line_open(iter);
		break;
	case TRACE_FILE_CLOSE:
		ret = print_line_close(iter);
		break;
	case TRACE_FILE_READ:
		ret = print_line_read(iter);
		break;
	case TRACE_FILE_WRITE:
		ret = print_line_write(iter);
		break;
	case TRACE_FILE_RDATA:
		ret = print_line_rdata(iter);
		break;
	case TRACE_FILE_WDATA:
		ret = print_line_wdata(iter);
		break;
	case TRACE_FILE_LSEEK:
		ret = print_line_lseek(iter);
		break;
	}

	return ret ? TRACE_TYPE_HANDLED : TRACE_TYPE_PARTIAL_LINE;
}

struct tracer file_tracer __read_mostly = {
	.name = "file_trace",
	.init = file_trace_init,
	.reset = file_trace_reset,
	.start = file_trace_start,
	.stop = file_trace_stop,
	.print_header = file_trace_print_header,
	.print_line = file_trace_print_line,
};
