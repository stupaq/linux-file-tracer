/**
 * A file_trace tracer.
 *
 * Copyright (C) 2013 Mateusz Machalica <mateuszmachalica@gmail.com>
 **/

#include <linux/limits.h>
#include <linux/ftrace.h>
#include <linux/namei.h>
#include "trace.h"

#include <trace/file_trace.h>

DEFINE_TRACE(file_open);
DEFINE_TRACE(file_close);
DEFINE_TRACE(file_read);
DEFINE_TRACE(file_write);
DEFINE_TRACE(file_lseek);

static struct trace_array *this_tracer = NULL;

/* Trace handlers */
static void probe_open(const char __user *__filename, int flags, int mode,
		long retval) {
	struct ring_buffer_event *event;
	struct file_open_entry *entry;
	size_t fsize;
	char *filename;
	
	if (!this_tracer)
		return;

	/* alloc filename */
	if (IS_ERR(filename = getname(__filename)))
		goto fail_filename;
	fsize = strnlen(filename, PATH_MAX - 1) + 1;

	/* alloc event */
	event = trace_buffer_lock_reserve(this_tracer->buffer, TRACE_FILE_OPEN,
			sizeof(*entry) + fsize, 0, 0);
	if (!event)
		goto fail_event;

	entry = ring_buffer_event_data(event);
	entry->flags = flags;
	entry->mode = mode;
	entry->retval = retval;
	strncpy(entry->filename, filename, fsize);
	entry->filename[fsize - 1]  = '\0';
	/* free event */
	trace_buffer_unlock_commit(this_tracer->buffer, event, 0, 0);
fail_event:
	/* free filename */
	putname(filename);
fail_filename:
	return;
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
	entry->fd = fd;
	entry->retval = retval;
	trace_buffer_unlock_commit(this_tracer->buffer, event, 0, 0);
}

static void helper_probe_data(unsigned int fd, const char __user *buf, size_t
		count, ssize_t retval, enum trace_type etype, enum trace_type
		dtype) {
	struct ring_buffer_event *event;
	/* It's ok since file_read/write_entry are binary compatible */
	struct file_read_entry *entry;
	ssize_t start, left;

	if (!this_tracer)
		return;
	/* Place file_read/write_entry */
	event = trace_buffer_lock_reserve(this_tracer->buffer, etype,
			sizeof(*entry), 0, 0);
	if (!event)
		return;
	entry = ring_buffer_event_data(event);
	entry->fd = fd;
	entry->count = count;
	entry->retval = retval;
	trace_buffer_unlock_commit(this_tracer->buffer, event, 0, 0);
	entry = NULL;
	event = NULL;
	/* Place file_r/wdata_entries */
	start = 0;
	left = retval;
	if (dtype == TRACE_FILE_WDATA)
		left = count;
	while(left > 0) {
		/* It's ok since file_r/wdata_entry are binary compatible */
		struct file_rdata_entry *data;
		char tmp[FILE_TRACE_MAX_DATA];
		ssize_t todo = min(FILE_TRACE_MAX_DATA, left);
		/* Todo == 0 means something gone wrong while copying */
		if (copy_from_user(tmp, buf + start, todo))
			todo = 0;
		/* We shall not lock trace buffer and sleep */
		event = trace_buffer_lock_reserve(this_tracer->buffer, dtype,
				sizeof(*data) + todo, 0, 0);
		if (!event)
			return;
		data = ring_buffer_event_data(event);
		data->length = todo;
		memmove(data->data, tmp, todo);
		trace_buffer_unlock_commit(this_tracer->buffer, event, 0, 0);
		left -= todo;
		start += todo;
		/* Do not continue after fault */
		if (todo == 0)
			break;
	}
}

static void probe_read(unsigned int fd, const char __user *buf, size_t count,
		ssize_t retval) {
	helper_probe_data(fd, buf, count, retval, TRACE_FILE_READ,
			TRACE_FILE_RDATA);
}

static void probe_write(unsigned int fd, const char __user *buf, size_t count,
		ssize_t retval) {
	helper_probe_data(fd, buf, count, retval, TRACE_FILE_WRITE,
			TRACE_FILE_WDATA);
}

static void probe_lseek(unsigned int fd, loff_t offset, unsigned int origin, int
		retval) {
	struct ring_buffer_event *event;
	struct file_lseek_entry *entry;

	if (!this_tracer)
		return;
	event = trace_buffer_lock_reserve(this_tracer->buffer, TRACE_FILE_LSEEK,
			sizeof(*entry), 0, 0);
	if (!event)
		return;
	entry = ring_buffer_event_data(event);
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
	if ((ret = register_trace_file_read(probe_read)))
		return ret;
	if ((ret = register_trace_file_write(probe_write)))
		return ret;
	if ((ret = register_trace_file_lseek(probe_lseek)))
		return ret;
	return ret;
}

static void file_trace_reset(struct trace_array *tr) {
	/* Unregister trace handlers */
	unregister_trace_file_lseek(probe_lseek);
	unregister_trace_file_write(probe_write);
	unregister_trace_file_read(probe_read);
	unregister_trace_file_close(probe_close);
	unregister_trace_file_open(probe_open);

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
	long retval;
	trace_assign_type(field, iter->ent);
	format = "%d OPEN %s %#x %#o SUCCESS %ld\n";
	retval = field->retval;
	if (IS_ERR_VALUE(retval)) {
		format = "%d OPEN %s %#x %#o ERR %ld\n";
		retval *= -1;
	}
	return trace_seq_printf(&iter->seq, format, iter->ent->pid,
			field->filename, field->flags, field->mode, retval);
}

static int print_line_close(struct trace_iterator *iter) {
	struct file_close_entry *field;
	trace_assign_type(field, iter->ent);
	if (IS_ERR_VALUE(field->retval))
		return trace_seq_printf(&iter->seq, "%d CLOSE %u ERR %d\n",
				iter->ent->pid, field->fd, field->retval);
	else
		return trace_seq_printf(&iter->seq, "%d CLOSE %u SUCCESS\n",
				iter->ent->pid, field->fd);
}

static int print_line_read(struct trace_iterator *iter) {
	struct file_read_entry *field;
	const char *format;
	ssize_t retval;
	trace_assign_type(field, iter->ent);
	retval = field->retval;
	if (retval == 0) {
		format = "%d READ %u %u EOF\n";
		return trace_seq_printf(&iter->seq, format, iter->ent->pid,
				field->fd, field->count);
	} else {
		format = "%d READ %u %u SUCCESS %d\n";
		if (IS_ERR_VALUE(retval)) {
			format = "%d READ %u %u ERR %d\n";
			retval *= -1;
		}
		return trace_seq_printf(&iter->seq, format, iter->ent->pid,
				field->fd, field->count, retval);
	}
}

static int print_line_write(struct trace_iterator *iter) {
	struct file_write_entry *field;
	const char *format;
	ssize_t retval;
	trace_assign_type(field, iter->ent);
	format = "%d WRITE %u %u SUCCESS %d\n";
	retval = field->retval;
	if (IS_ERR_VALUE(retval)) {
		format = "%d WRITE %u %u ERR %d\n";
		retval *= -1;
	}
	return trace_seq_printf(&iter->seq, format, iter->ent->pid, field->fd,
			field->count, retval);
}

static int helper_print_data(struct trace_seq *seq, const char *data, ssize_t
		length) {
	ssize_t i;
	int ret;
	for (i = 0; i < length; ++i) {
		if (!(ret = trace_seq_printf(seq, " %02hhx", data[i])))
			return ret;
	}
	return trace_seq_printf(seq, "\n");
}

static int print_line_rdata(struct trace_iterator *iter) {
	struct file_rdata_entry *field;
	int ret;
	trace_assign_type(field, iter->ent);
	ret = trace_seq_printf(&iter->seq, "%d READ_DATA", iter->ent->pid);
	if (!ret)
		return ret;
	if (field->length)
		ret = helper_print_data(&iter->seq, field->data, field->length);
	else
		ret = trace_seq_printf(&iter->seq, " READ_DATA_FAULT\n");
	return ret;
}

static int print_line_wdata(struct trace_iterator *iter) {
	struct file_wdata_entry *field;
	int ret;
	trace_assign_type(field, iter->ent);
	ret = trace_seq_printf(&iter->seq, "%d WRITE_DATA", iter->ent->pid);
	if (!ret)
		return ret;
	if (field->length)
		ret = helper_print_data(&iter->seq, field->data, field->length);
	else
		ret = trace_seq_printf(&iter->seq, " WRITE_DATA_FAULT\n");
	return ret;
}

static int print_line_lseek(struct trace_iterator *iter) {
	struct file_lseek_entry *field;
	const char *format;
	int retval;
	trace_assign_type(field, iter->ent);
	format = "%d LSEEK %u %lld %u SUCCESS %d\n";
	retval = field->retval;
	if (IS_ERR_VALUE(retval)) {
		format = "%d LSEEK %u %lld %u ERR %d\n";
		retval *= -1;
	}
	return trace_seq_printf(&iter->seq, format, iter->ent->pid, field->fd,
			field->offset, field->origin, retval);
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
