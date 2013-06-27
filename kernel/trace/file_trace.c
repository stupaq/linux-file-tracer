/**
 * A file_trace tracer.
 *
 * Copyright (C) 2013 Mateusz Machalica <mateuszmachalica@gmail.com>
 **/

#include <linux/limits.h>
#include <linux/ftrace.h>
#include "trace.h"

#include <trace/file_trace.h>

DEFINE_TRACE(file_open);
DEFINE_TRACE(file_close);
DEFINE_TRACE(file_lseek);

static struct trace_array *this_tracer = NULL;

/* Trace handlers */
static void probe_open(const char *filename, int flags, int mode,
		long retval) {
	struct ring_buffer_event *event;
	struct file_open_entry *entry;
	size_t fsize = strnlen(filename, PATH_MAX - 1) + 1;

	if (!this_tracer)
		return;
	event = trace_buffer_lock_reserve(this_tracer->buffer, TRACE_FILE_OPEN,
			sizeof(*entry) + fsize, 0, 0);
	if (!event)
		return;
	entry = ring_buffer_event_data(event);
	entry->pid = task_pid_nr(current);
	entry->flags = flags;
	entry->mode = mode;
	entry->retval = retval;
	strncpy(entry->filename, filename, fsize);
	entry->filename[fsize - 1]  = '\0';
	trace_buffer_unlock_commit(this_tracer->buffer, event, 0, 0);
}

static void probe_close(unsigned int fd, int retval) {
	struct ring_buffer_event *event;
	struct file_close_entry *entry;

	if (!this_tracer)
		return;
	event = trace_buffer_lock_reserve(this_tracer->buffer, TRACE_FILE_CLOSE,
			sizeof(*entry), 0, 0);
	if (!event)
		return;
	entry = ring_buffer_event_data(event);
	entry->pid = task_pid_nr(current);
	entry->fd = fd;
	entry->retval = retval;
	trace_buffer_unlock_commit(this_tracer->buffer, event, 0, 0);
}

static void probe_lseek(unsigned int fd, loff_t offset, int origin, int retval)
{
	struct ring_buffer_event *event;
	struct file_lseek_entry *entry;

	if (!this_tracer)
		return;
	event = trace_buffer_lock_reserve(this_tracer->buffer, TRACE_FILE_LSEEK,
			sizeof(*entry), 0, 0);
	if (!event)
		return;
	entry = ring_buffer_event_data(event);
	entry->pid = task_pid_nr(current);
	entry->fd = fd;
	entry->offset = offset;
	entry->origin = origin;
	entry->retval = retval;
	trace_buffer_unlock_commit(this_tracer->buffer, event, 0, 0);
}

/* Tracer instrumentation */
static void file_trace_start(struct trace_array *tr) {
	this_tracer = tr;
}

static void file_trace_stop(struct trace_array *tr) {
	this_tracer = NULL;
}

static int file_trace_init(struct trace_array *tr) {
	int ret;
	tracing_reset_online_cpus(tr);
	file_trace_start(tr);
	/* Register trace handlers */
	if ((ret = register_trace_file_open(probe_open)))
		return ret;
	if ((ret = register_trace_file_close(probe_close)))
		return ret;
	if ((ret = register_trace_file_lseek(probe_lseek)))
		return ret;
	return ret;
}

static void file_trace_reset(struct trace_array *tr) {
	/* Unregister trace handlers */
	register_trace_file_open(probe_open);
	register_trace_file_close(probe_close);
	register_trace_file_lseek(probe_lseek);

	file_trace_stop(tr);
	tracing_reset_online_cpus(tr);
}

static void file_trace_print_header(struct seq_file *s) {
	seq_puts(s, "");
}

/* Per-event printfs */
static int print_line_open(struct trace_iterator *iter) {
	struct file_open_entry *field;
	const char *format;

	trace_assign_type(field, iter->ent);
	format = "%d OPEN %s %#x %#o SUCCESS %d\n";
	if (IS_ERR_VALUE(field->retval)) {
		format = "%d OPEN %s %#x %#o ERR %d\n";
		field->retval *= -1;
	}
	return trace_seq_printf(&iter->seq, format, field->pid, field->filename,
			field->flags, field->mode, field->retval);
}

static int print_line_close(struct trace_iterator *iter) {
	struct file_close_entry *field;
	trace_assign_type(field, iter->ent);
	if (IS_ERR_VALUE(field->retval))
		return trace_seq_printf(&iter->seq, "%d CLOSE %d ERR %d\n",
				field->pid, field->fd, field->retval);
	else
		return trace_seq_printf(&iter->seq, "%d CLOSE %d SUCCESS\n",
				field->pid, field->fd);
}

static int print_line_read(struct trace_iterator *iter) {
	struct file_read_entry *field;
	const char *format;
	trace_assign_type(field, iter->ent);
	format = "%d READ %d %d SUCCESS %d\n";
	if (IS_ERR_VALUE(field->retval)) {
		format = "%d READ %d %d ERR %d\n";
		field->retval *= -1;
	}
	return trace_seq_printf(&iter->seq, format, field->pid, field->fd,
			field->count, field->retval);
}

static int print_line_write(struct trace_iterator *iter) {
	struct file_write_entry *field;
	const char *format;
	trace_assign_type(field, iter->ent);
	format = "%d WRITE %d %d SUCCESS %d\n";
	if (IS_ERR_VALUE(field->retval)) {
		format = "%d WRITE %d %d ERR %d\n";
		field->retval *= -1;
	}
	return trace_seq_printf(&iter->seq, format, field->pid, field->fd,
			field->count, field->retval);
}

static int print_line_rdata(struct trace_iterator *iter) {
	struct file_rdata_entry *field;
	trace_assign_type(field, iter->ent);
	if (field->length) {
		// TODO
		return 1;
	} else return trace_seq_printf(&iter->seq, "READ_DATA_FAULT\n");
}

static int print_line_wdata(struct trace_iterator *iter) {
	struct file_wdata_entry *field;
	trace_assign_type(field, iter->ent);
	if (field->length) {
		// TODO
		return 1;
	} else return trace_seq_printf(&iter->seq, "WRITE_DATA_FAULT\n");
}

static int print_line_lseek(struct trace_iterator *iter) {
	struct file_lseek_entry *field;
	const char *format;
	trace_assign_type(field, iter->ent);
	format = "%d LSEEK %d %d %d SUCCESS %d\n";
	if (IS_ERR_VALUE(field->retval)) {
		format = "%d LSEEK %d %d %d ERR %d\n";
		field->retval *= -1;
	}
	return trace_seq_printf(&iter->seq, format, field->pid, field->fd,
			field->offset, field->origin, field->retval);
}

/* Printf dispatcher */
static enum print_line_t file_trace_print_line(struct trace_iterator *iter) {
	int ret = 1;

	switch (iter->ent->type) {
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
	default:
		return TRACE_TYPE_UNHANDLED;
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
