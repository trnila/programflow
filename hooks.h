#pragma once

int hook_read(struct tracy_event * e);
int hook_write(struct tracy_event * e);
int hook_fork(struct tracy_event *e);
int hook_execve(struct tracy_event *e);
int hook_sendmsg(struct tracy_event *e);
