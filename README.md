# BarnOwlD - A Cache Side-Channel Real Time Attack Detector

**The name is inspired by a barn owl, which has one of the best hearing in the
animal world. Just the thing to detect microscopic but massive cache misses and
other unnatural behavior.  Or because the name can easily be turned into a cute
logo and was still free as a project name. You can choose the reason yourself.**

Idea of the daemon: try to detect unnatural CPU characteristics with as little
computational effort as possible, which can be traced back to side-channel
attacks with a very high probability. If these are detected, report the whole
thing to the system log. Log monitoring systems for cloud systems, for example,
can trigger a warning when these messages are detected.

# PoC Test Disclaimer

Some of the tests may not work out of the box at your PC. Some PoCs can only be
executed if Meltdown/Spectre Linux Kernel counter measures are disabled.

If you use updated microcode to fix speculative execution side-channel attacks
some of the provided PoCs may also not work at your local PC.


# References

- https://yinqian.org/papers/dimva21.pdf
