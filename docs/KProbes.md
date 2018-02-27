# KProbes

  * [What](#what)
  * [Why](#why)
  * [How](#how)
  * [Capsule8 KProbes](#capsule8-kprobes)
  * [Further Reading](#further-reading)

### What

KProbes are a way to trace events happening inside of the linux kernel. They are attached to symbols in kernel source code such that everytime that symbol is called an event will be reported. Available symbols to attach to can be read from `/proc/kallsyms` as the root user.

### Why

KProbes are useful for debugging performance bottlenecks, logging specific events, debugging kernel functionality, and many other applications. Capsule8 utilizes KProbes (and other mechanisms) for security analysis. See the Capsule8 KProbes section bellow for specific examples.

### How

KProbes work by inserting a breakpoint at the begining of the function being probed. Pre and Post handlers are associated with each probe which are executed before and after the probed function is called. KProbes can be loaded via unix utilies (see further reading) or via the Event Monitor library located in `pkg/sys/perf`

### Capsule8 KProbes

When you have the Capsule8 sensor running, reading `/sys/kernel/debug/tracing/kprobe_events` will give you some information about the currently loaded kprobes:

```
p:capsule8/sensor_18949_1 commit_creds usage=+0(%di):u64 uid=+8(%di):u32 gid=+12(%di):u32 suid=+16(%di):u32 sgid=+20(%di):u32 euid=+24(%di):u32 egid=+28(%di):u32 fsuid=+32(%di):u32 fsgid=+36(%di):u32
p:capsule8/sensor_18949_3 sys_execve argv0=+0(+0(%si)):string argv1=+0(+8(%si)):string argv2=+0(+16(%si)):string argv3=+0(+24(%si)):string argv4=+0(+32(%si)):string argv5=+0(+40(%si)):string
p:capsule8/sensor_18949_4 do_execve argv0=+0(+0(%si)):string argv1=+0(+8(%si)):string argv2=+0(+16(%si)):string argv3=+0(+24(%si)):string argv4=+0(+32(%si)):string argv5=+0(+40(%si)):string
p:capsule8/sensor_18949_5 sys_execveat argv0=+0(+0(%dx)):string argv1=+0(+8(%dx)):string argv2=+0(+16(%dx)):string argv3=+0(+24(%dx)):string argv4=+0(+32(%dx)):string argv5=+0(+40(%dx)):string
p:capsule8/sensor_18949_6 do_execveat argv0=+0(+0(%dx)):string argv1=+0(+8(%dx)):string argv2=+0(+16(%dx)):string argv3=+0(+24(%dx)):string argv4=+0(+32(%dx)):string argv5=+0(+40(%dx)):string
p:capsule8/sensor_18949_7 sys_renameat newname=+0(%cx):string
p:capsule8/sensor_18949_8 sys_unlinkat pathname=+0(%si):string
```

As an example above we can see that there's a KProbe for commit_creds which is a kernel function for changing the credentials of a running task

_Note: The Capsule8 sensor will dynamically load KProbes depending on active subscriptions, system versions, and other factors._

### Further Reading

- [LWN.net - An introduction to KProbes](https://lwn.net/Articles/132196/)
- [Kernel.org KProbe documentation](https://www.kernel.org/doc/Documentation/kprobes.txt)
- [Kernel debugging with Kprobes](https://www.ibm.com/developerworks/library/l-kprobes/index.html)