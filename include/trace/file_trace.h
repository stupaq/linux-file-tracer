#ifndef _TRACE_FILE_TRACE_H
#define _TRACE_FILE_TRACE_H

#include <linux/kernel.h>
#include <linux/xattr.h>

#define FILE_TRACE_ATTR "user.file_trace"

static __always_inline void file_trace_setup(struct file *f) {
	f->f_tracing = vfs_getxattr(f->f_dentry, FILE_TRACE_ATTR, NULL, 0) >= 0;
}

void file_trace_open(const char __user *filename, int flags, int mode, long
		retval);

void file_trace_close(unsigned int fd, int retval);

void probe_lseek(unsigned int fd, loff_t offset, int origin, int retval);

#endif  /* _TRACE_FILE_TRACE_H */
