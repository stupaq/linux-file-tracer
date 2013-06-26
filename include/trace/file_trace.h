#ifndef _TRACE_FILE_TRACE_H
#define _TRACE_FILE_TRACE_H

#define CREATE_TRACE_POINTS
#include <trace/events/file_trace.h>

static __always_inline
void trace_file_trace_close(unsigned int fd, int retval) {
	if (IS_ERR_VALUE(retval))
		trace_file_trace_close_bad(fd, retval);
	else
		trace_file_trace_close_ok(fd);
}

#endif  /* _TRACE_FILE_TRACE_H */
