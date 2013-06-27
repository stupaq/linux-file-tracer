#ifndef _TRACE_FILE_TRACE_H
#define _TRACE_FILE_TRACE_H

#include <linux/kernel.h>
#include <linux/xattr.h>

#define FILE_TRACE_ATTR "user.file_trace"

static __always_inline void file_trace_setup(struct file *f) {
	f->f_tracing = vfs_getxattr(f->f_dentry, FILE_TRACE_ATTR, NULL, 0) >= 0;
}

#endif  /* _TRACE_FILE_TRACE_H */
