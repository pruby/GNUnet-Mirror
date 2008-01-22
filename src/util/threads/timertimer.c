/**
 * Program to check which timer function is fastest.
 * Must be linked with "-lrt", only works on 686.
 */

#include <sys/times.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>

static unsigned long long ticks;

static unsigned long long callibrate;

static unsigned long long
use_times ()
{
  struct tms t;
  return times (&t) * 1000L / ticks;
}

static unsigned long long
use_gtod ()
{
  struct timeval tv;
  struct timezone tz;
  gettimeofday (&tv, &tz);
  return (((unsigned long long) tv.tv_sec) * 1000) + (tv.tv_usec / 1000);
}

static unsigned long long
use_clock ()
{
  struct timespec ts;

  clock_gettime (CLOCK_REALTIME, &ts);
  return (((unsigned long long) ts.tv_sec) * 1000) + (ts.tv_nsec / 1000000);
}

static __inline__ unsigned long long
rdtsc ()
{
  unsigned long long x;
  __asm__ volatile ("rdtsc":"=A" (x));
  return x;
}

static unsigned long long
use_asm ()
{
  return rdtsc () / callibrate;
}

int
main (int argc, char **argv)
{
  unsigned long long l;
  unsigned long long start;
  unsigned long long g_start;
  unsigned long long cstart;

  l = 0;
  ticks = sysconf (_SC_CLK_TCK);
  g_start = use_gtod ();
  cstart = rdtsc ();
  start = use_times ();
  while ((use_times () - start) < 5 * 1000)
    l++;
  fprintf (stdout, "Could do %llu times calls in %llu ms\n", l,
           use_gtod () - g_start);
  callibrate = (rdtsc () - cstart) / 5000;

  l = 0;
  g_start = use_gtod ();
  start = use_gtod ();
  while ((use_gtod () - start) < 5 * 1000)
    l++;
  fprintf (stdout, "Could do %llu gtod  calls in %llu ms\n", l,
           use_gtod () - g_start);

  l = 0;
  g_start = use_gtod ();
  start = use_clock ();
  while ((use_clock () - start) < 5 * 1000)
    l++;
  fprintf (stdout, "Could do %llu clock calls in %llu ms\n", l,
           use_gtod () - g_start);

  l = 0;
  g_start = use_gtod ();
  start = use_asm ();
  while ((use_asm () - start) < 5 * 1000)
    l++;
  fprintf (stdout, "Could do %llu rdtsc calls in %llu ms\n", l,
           use_gtod () - g_start);
  return 0;

}
