#ifndef _TRACE_FILE_TRACE_H
#define _TRACE_FILE_TRACE_H

#include <linux/kernel.h>
#include <linux/xattr.h>
#include <linux/fs.h>
#include <linux/tracepoint.h>

DECLARE_TRACE(file_open,
	TP_PROTO(const char *filename, int flags, int mode, long retval),
	TP_ARGS(filename, flags, mode, retval));

DECLARE_TRACE(file_close,
	TP_PROTO(unsigned int fd, int retval),
	TP_ARGS(fd, retval));

DECLARE_TRACE(file_read,
	TP_PROTO(unsigned int fd, const char __user *buf, size_t count, ssize_t
		retval),
	TP_ARGS(fd, buf, count, retval));

DECLARE_TRACE(file_write,
	TP_PROTO(unsigned int fd, const char __user *buf, size_t count, ssize_t
		retval),
	TP_ARGS(fd, buf, count, retval));

DECLARE_TRACE(file_lseek,
	TP_PROTO(unsigned int fd, loff_t offset, unsigned int origin, int
		retval),
	TP_ARGS(fd, offset, origin, retval));

static __always_inline bool file_trace_enabled(struct file *f) {
#ifdef CONFIG_TRACING
	return f && f->f_tracing;
#else
	return false;
#endif
}

static __always_inline void file_trace_setup(struct file *f) {
#ifdef CONFIG_TRACING
#define FILE_TRACE_ATTR "user.file_trace"
	f->f_tracing = (__vfs_getxattr_noperm(f->f_dentry, FILE_TRACE_ATTR,
				NULL, 0) >= 0);
#endif
}

#endif  /* _TRACE_FILE_TRACE_H */
