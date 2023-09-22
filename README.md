# BarnOwlD - A Daemon for Real-Time Detection of Cache Side-Channel Attacks

**The name is inspired by a barn owl, which has one of the best hearing in the
animal world. Just the thing to detect microscopic but massive cache misses and
other unnatural behavior.  Or because the name can easily be turned into a cute
logo and was still free as a project name. You can choose the reason yourself.**

Idea of the daemon: try to detect unnatural CPU characteristics with as little
computational effort as possible, which can be traced back to side-channel
attacks with a very high probability. If these are detected, report the whole
thing to the system log. Log monitoring systems for cloud systems, for example,
can trigger a warning when these messages are detected.

# Implementation Aspects

Barnowld analyzes all available logical CPUs (hardware threads, called Harts in
the RISC-V world) for abnormalities over a certain period of time. In doing so,
it iterates over time and in a pseudo-random fashion over the CPUs to make
countermeasures more difficult. Then Barnowl analyzes the cache reference and
cache missrate for a certain amount of time - again pseudo-randomly. Here
especially the last level cache charactetristics.

For this purpose Barnwold uses the so-called Counting Mode of the Performance
Monitor Unit (PMU) of the processor. In contrast to the Sampling Mode, the
Counting Mode has no measurable overhead.

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
