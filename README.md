# BarnOwlD - A Daemon for Real-Time Detection of Cache Side-Channel Attacks

*The name is inspired by a barn owl, which has one of the best hearing in the
animal world. Just the thing to detect microscopic but massive cache misses and
other unnatural behavior.  Or because the name can easily be turned into a cute
logo and was still free as a project name. You can choose the reason yourself.*

**Warning:** barnowld is a PoC project. I have tested it with many different
side-channel PoCs, and carefully tuned thresholds, but in the end it needs more
validation to be used productively!

---

Idea of the daemon: try to detect unnatural CPU characteristics with as little
computational effort as possible, which can be traced back to side-channel
attacks with a very high probability. If these are detected, report the whole
thing to the system log. Log monitoring systems for cloud systems, for example,
can trigger a warning when these messages are detected.

Some scientific publications are available on the Internet. The problem with
these is that they often involve machine learning and other compute intensive
requirements or are complex to operate (in terms of CPU resources). In
addition, the source code is usually not available, why I decided to implement
this independently in this form. But I am always grateful for

# Implementation Aspects

Barnowld analyzes all available logical CPUs (hardware threads, called Harts in
the RISC-V world) for abnormalities over a certain period of time. In doing so,
it iterates over time and in a pseudo-random fashion over the CPUs to make
countermeasures more difficult. Then Barnowl analyzes the cache reference and
cache missrate for a certain amount of time - again pseudo-randomly. Here
especially the last level cache charactetristics.

For this purpose Barnwold uses the so-called Counting Mode of the Performance
Monitor Unit (PMU) of the processor. In contrast to the Sampling Mode, the
Counting Mode has defacto no measurable overhead. Also PMUs are available for
all major platforms from Intel, AMD, ARM or RISC-V.

The whole thing is based on the perf subsystem of the Linux kernel which is
designed around two aspects: flexibility and performance. In fact, perf can be
seen as a command system call, which efficiently exchanges data between kernel
space and user space using a ring buffer. So ideal conditions if these analyses
are to be made with lowest overhead.

# PoC Test Disclaimer

Some of the tests may not work out of the box at your PC. Some PoCs can only be
executed if Meltdown/Spectre Linux Kernel counter measures are disabled.

If you use updated microcode to fix speculative execution side-channel attacks
some of the provided PoCs may also not work at your local PC.


# References

- https://yinqian.org/papers/dimva21.pdf
