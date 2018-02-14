# FAQ

### How is this supposed to be used?

The Capsule8 sensor is intended to be run on a Linux host persistently and
ideally before the host begins running application workloads. It is
designed to support API clients subscribing and unsubcribing from
telemetry dynamically to implement various security incident detection
strategies.

### What types of events can be subscribed to currently?

Container lifecycle, process lifecycle, raw system calls, file opens,
network activity, and kernel function calls.

### Kernel function calls?

You can subscribe to calls to a chosen exported function symbol and
receive telemetry events with named values of the data requested. This
data can include function call arguments, return values, register
values, and even values dereferences via offsets from any of them. For
a more detailed description of what's possible, see the Linux kernel
[kprobe docs](https://www.kernel.org/doc/Documentation/trace/kprobetrace.txt).

### What guarantees does the Sensor provide?

The Capsule8 sensor provides telemetry events on a best-effort
basis. System-level events are intentionally monitored through
`perf_event_open(2)` such that an excessive volume of events causes
them to be dropped by the kernel rather than blocking the kernel as
the audit subsystem may do. This means that telemetry events, and even
some of the information within them, is "lossy" by design. We believe
that this is the right trade-off for monitoring production
environments where stability and performance are critical.
