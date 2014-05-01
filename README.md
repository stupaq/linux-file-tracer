Linux 2.6.34.8 kernel per-file syscalls tracing
===============================================

Introduction
------------

Implementation utilizes `ftrace` interface for non-intrusive tracepoints.  The
following syscalls are traced: `open`, `close`, `read`, `write` and `lseek`.

Setup
-----

Tracing is enabled on a per-file basis by setting (to any value) special
extended attribute `user.file_trace`. In order for `file_tracer` to be present
in compiled kernel `CONFIG_TRACING` entry must be set in `.config` file.

Details
-------

Presence of `user.file_trace` attribute is determined with no respect to
attributes access permissions of the calling process. Since tracing interface
should never be exposed to unprivileged user this design poses no danger to
widely understand system security.


Brought to the world by Mateusz Machalica.
