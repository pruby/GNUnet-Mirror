/*
     This file is part of GNUnet.
     (C) 2005 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file util/win/win_printf.c
 * @brief Unix compatible printf for Windows
 * @author Felix von Leitner
 * @author Nils Durner
 * @see <a href="http://www.fefe.de/dietlibc/">diet libc</a>
 */

/* Stolen from Felix von Leitners "diet libc" 0.28 */
 
#include <stdarg.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <io.h>

#define WANT_ERROR_PRINTF 1
#define WANT_LONGLONG_PRINTF 1
#define WANT_NULL_PRINTF 1
#define WANT_FLOATING_POINT_IN_PRINTF 1

#define WANT_FLOATING_POINT_IN_SCANF
#define WANT_LONGLONG_SCANF
#define WANT_CHARACTER_CLASSES_IN_SCANF

struct str_data {
  unsigned char* str;
  size_t len;
  size_t size;
};

struct arg_printf {
  void *data;
  int (*put)(void*,size_t,void*);
};

static inline unsigned int skip_to(const unsigned char *format) {
  unsigned int nr;
  for (nr=0; format[nr] && (format[nr]!='%'); ++nr);
  return nr;
}

#define A_WRITE(fn,buf,sz)	((fn)->put((void*)(buf),(sz),(fn)->data))

static const char pad_line[2][16]= { "                ", "0000000000000000", };
static inline int write_pad(struct arg_printf* fn, int len, int padwith) {
  int nr=0;
  for (;len>15;len-=16,nr+=16) {
    A_WRITE(fn,pad_line[(padwith=='0')?1:0],16);
  }
  if (len>0) {
    A_WRITE(fn,pad_line[(padwith=='0')?1:0],(unsigned int)len); nr+=len;
  }
  return nr;
}

int __lltostr(char *s, int size, unsigned long long i, int base, char UpCase)
{
  char *tmp;
  unsigned int j=0;

  s[--size]=0;

  tmp=s+size;

  if ((base==0)||(base>36)) base=10;

  j=0;
  if (!i)
  {
    *(--tmp)='0';
    j=1;
  }

  while((tmp>s)&&(i))
  {
    tmp--;
    if ((*tmp=i%base+'0')>'9') *tmp+=(UpCase?'A':'a')-'9'-1;
    i=i/base;
    j++;
  }
  memmove(s,tmp,j+1);

  return j;
}

int __ltostr(char *s, unsigned int size, unsigned long i, unsigned int base, int UpCase)
{
  char *tmp;
  unsigned int j=0;

  s[--size]=0;

  tmp=s+size;

  if ((base==0)||(base>36)) base=10;

  j=0;
  if (!i)
  {
    *(--tmp)='0';
    j=1;
  }

  while((tmp>s)&&(i))
  {
    tmp--;
    if ((*tmp=i%base+'0')>'9') *tmp+=(UpCase?'A':'a')-'9'-1;
    i=i/base;
    j++;
  }
  memmove(s,tmp,j+1);

  return j;
}

static int copystring(char* buf,int maxlen, const char* s) {
  int i;
  for (i=0; i<3&&i<maxlen; ++i)
    buf[i]=s[i];
  if (i<maxlen) { buf[i]=0; ++i; }
  return i;
}

int isinf(double d) {
  union {
    unsigned long long l;
    double d;
  } u;
  u.d=d;
  return (u.l==0x7FF0000000000000ll?1:u.l==0xFFF0000000000000ll?-1:0);
}

int isnan(double d) {
  union {
    unsigned long long l;
    double d;
  } u;
  u.d=d;
  return (u.l==0x7FF8000000000000ll || u.l==0x7FF0000000000000ll || u.l==0xfff8000000000000ll);
}

int __dtostr(double d,char *buf,unsigned int maxlen,unsigned int prec,unsigned int prec2) {
#if 1
  union {
    unsigned long long l;
    double d;
  } u = { .d=d };
  /* step 1: extract sign, mantissa and exponent */
  signed long e=((u.l>>52)&((1<<11)-1))-1023;
#else
#if __BYTE_ORDER == __LITTLE_ENDIAN
  signed long e=(((((unsigned long*)&d)[1])>>20)&((1<<11)-1))-1023;
#else
  signed long e=(((*((unsigned long*)&d))>>20)&((1<<11)-1))-1023;
#endif
#endif
/*  unsigned long long m=u.l & ((1ull<<52)-1); */
  /* step 2: exponent is base 2, compute exponent for base 10 */
  signed long e10;
  /* step 3: calculate 10^e10 */
  unsigned int i;
  double backup=d;
  double tmp;
  char *oldbuf=buf;

  if ((i=isinf(d))) return copystring(buf,maxlen,i>0?"inf":"-inf");
  if (isnan(d)) return copystring(buf,maxlen,"nan");
  e10=1+(long)(e*0.30102999566398119802); /* log10(2) */
  /* Wir iterieren von Links bis wir bei 0 sind oder maxlen erreicht
   * ist.  Wenn maxlen erreicht ist, machen wir das nochmal in
   * scientific notation.  Wenn dann von prec noch was übrig ist, geben
   * wir einen Dezimalpunkt aus und geben prec2 Nachkommastellen aus.
   * Wenn prec2 Null ist, geben wir so viel Stellen aus, wie von prec
   * noch übrig ist. */
  if (d==0.0) {
    prec2=prec2==0?1:prec2+2;
    prec2=prec2>maxlen?8:prec2;
    i=0;
    if (prec2 && (long long)u.l<0) { buf[0]='-'; ++i; }
    for (; i<prec2; ++i) buf[i]='0';
    buf[buf[0]=='0'?1:2]='.'; buf[i]=0;
    return i;
  }

  if (d < 0.0) { d=-d; *buf='-'; --maxlen; ++buf; }

   /*
      Perform rounding. It needs to be done before we generate any
      digits as the carry could propagate through the whole number.
   */

  tmp = 0.5;
  for (i = 0; i < prec2; i++) { tmp *= 0.1; }
  d += tmp;

  if (d < 1.0) { *buf='0'; --maxlen; ++buf; }
/*  printf("e=%d e10=%d prec=%d\n",e,e10,prec); */
  if (e10>0) {
    int first=1;	/* are we about to write the first digit? */
    tmp = 10.0;
    i=e10;
    while (i>10) { tmp=tmp*1e10; i-=10; }
    while (i>1) { tmp=tmp*10; --i; }
    /* the number is greater than 1. Iterate through digits before the
     * decimal point until we reach the decimal point or maxlen is
     * reached (in which case we switch to scientific notation). */
    while (tmp>0.9) {
      char digit;
      double fraction=d/tmp;
	digit=(int)(fraction);		/* floor() */
      if (!first || digit) {
	first=0;
	*buf=digit+'0'; ++buf;
	if (!maxlen) {
	  /* use scientific notation */
	  int len=__dtostr(backup/tmp,oldbuf,maxlen,prec,prec2);
	  int initial=1;
	  if (len==0) return 0;
	  maxlen-=len; buf+=len;
	  if (maxlen>0) {
	    *buf='e';
	    ++buf;
	  }
	  --maxlen;
	  for (len=1000; len>0; len/=10) {
	    if (e10>=len || !initial) {
	      if (maxlen>0) {
		*buf=(e10/len)+'0';
		++buf;
	      }
	      --maxlen;
	      initial=0;
	      e10=e10%len;
	    }
	  }
	  if (maxlen>0) goto fini;
	  return 0;
	}
	d-=digit*tmp;
	--maxlen;
      }
      tmp/=10.0;
    }
  }
  else
  {
     tmp = 0.1;
  }

  if (buf==oldbuf) {
    if (!maxlen) return 0; --maxlen;
    *buf='0'; ++buf;
  }
  if (prec2 || prec>(unsigned int)(buf-oldbuf)+1) {	/* more digits wanted */
    if (!maxlen) return 0; --maxlen;
    *buf='.'; ++buf;
    prec-=buf-oldbuf-1;
    if (prec2) prec=prec2;
    if (prec>maxlen) return 0;
    while (prec>0) {
      char digit;
      double fraction=d/tmp;
      digit=(int)(fraction);		/* floor() */
      *buf=digit+'0'; ++buf;
      d-=digit*tmp;
      tmp/=10.0;
      --prec;
    }
  }
fini:
  *buf=0;
  return buf-oldbuf;
}

int __v_printf(struct arg_printf* fn, const unsigned char *format, va_list arg_ptr)
{
  int len=0;
#ifdef WANT_ERROR_PRINTF
  int _my_errno = errno;
#endif

  while (*format) {
    unsigned int sz = skip_to(format);
    if (sz) {
      A_WRITE(fn,format,sz); len+=sz;
      format+=sz;
    }
    if (*format=='%') {
      char buf[128];
      union { char*s; } u_str;
#define s u_str.s

      int retval;
      unsigned char ch, padwith=' ';

      char flag_in_sign=0;
      char flag_upcase=0;
      char flag_hash=0;
      char flag_left=0;
      char flag_space=0;
      char flag_sign=0;
      char flag_dot=0;
      signed char flag_long=0;

      unsigned int base;
      unsigned int width=0, preci=0;

      long number=0;
#ifdef WANT_LONGLONG_PRINTF
      long long llnumber=0;
#endif

      ++format;
inn_printf:
      switch(ch=*format++) {
      case 0:
	return -1;
	break;

      /* FLAGS */
      case '#':
	flag_hash=-1;
      case 'z':
	goto inn_printf;

      case 'h':
	--flag_long;
	goto inn_printf;
      case 'q':		/* BSD ... */
      case 'L':
	++flag_long; /* fall through */
      case 'l':
	++flag_long;
	goto inn_printf;

      case '-':
	flag_left=1;
	goto inn_printf;

      case ' ':
	flag_space=1;
	goto inn_printf;

      case '+':
	flag_sign=1;
	goto inn_printf;

      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
	if(flag_dot) return -1;
	width=strtoul(format-1,(char**)&s,10);
	if (ch=='0' && !flag_left) padwith='0';
	format=s;
	goto inn_printf;

      case '*':
	width=va_arg(arg_ptr,int);
	goto inn_printf;

      case '.':
	flag_dot=1;
	if (*format=='*') {
	  int tmp=va_arg(arg_ptr,int);
	  preci=tmp<0?0:tmp;
	  ++format;
	} else {
	  long int tmp=strtol(format,(char**)&s,10);
	  preci=tmp<0?0:tmp;
	  format=s;
	}
	goto inn_printf;

      /* print a char or % */
      case 'c':
	ch=(char)va_arg(arg_ptr,int);
      case '%':
	A_WRITE(fn,&ch,1); ++len;
	break;

#ifdef WANT_ERROR_PRINTF
      /* print an error message */
      case 'm':
	s=strerror(_my_errno);
	sz=strlen(s);
	A_WRITE(fn,s,sz); len+=sz;
	break;
#endif
      /* print a string */
      case 's':
	s=va_arg(arg_ptr,char *);
#ifdef WANT_NULL_PRINTF
	if (!s) s="(null)";
#endif
	sz = strlen(s);
	if (flag_dot && sz>preci) sz=preci;
	preci=0;
	flag_dot^=flag_dot;
	padwith=' ';

print_out:
      {
	char *sign=s;
	int todo=0;
	int vs;
	
	if (! (width||preci) ) {
	  A_WRITE(fn,s,sz); len+=sz;
	  break;
	}
	
	if (flag_in_sign) todo=1;
	if (flag_hash>0)  todo=flag_hash;
	if (todo) {
	  s+=todo;
	  sz-=todo;
	  width-=todo;
	}
	
	if (!flag_left) {
	  if (flag_dot) {
	    vs=preci>sz?preci:sz;
	    len+=write_pad(fn,(signed int)width-(signed int)vs,' ');
	    if (todo) {
	      A_WRITE(fn,sign,todo);
	      len+=todo;
	    }
	    len+=write_pad(fn,(signed int)preci-(signed int)sz,'0');
	  } else {
	    if (todo && padwith=='0') {
	      A_WRITE(fn,sign,todo);
	      len+=todo; todo=0;
	    }
	    len+=write_pad(fn,(signed int)width-(signed int)sz, padwith);
	    if (todo) {
	      A_WRITE(fn,sign,todo);
	      len+=todo;
	    }
	  }
	  A_WRITE(fn,s,sz); len+=sz;
	} else if (flag_left) {
	  if (todo) {
	    A_WRITE(fn,sign,todo);
	    len+=todo;
	  }
	  len+=write_pad(fn,(signed int)preci-(signed int)sz, '0');
	  A_WRITE(fn,s,sz); len+=sz;
	  vs=preci>sz?preci:sz;
	  len+=write_pad(fn,(signed int)width-(signed int)vs, ' ');
	} else {
	  A_WRITE(fn,s,sz); len+=sz;
	}
	break;
      }

      /* print an integer value */
      case 'b':
	base=2;
	sz=0;
	goto num_printf;
      case 'p':
	flag_hash=2;
	flag_long=1;
	ch='x';
      case 'X':
	flag_upcase=(ch=='X');
      case 'x':
	base=16;
	sz=0;
	if (flag_hash) {
	  buf[1]='0';
	  buf[2]=ch;
	  flag_hash=2;
	  sz=2;
	}
	if (preci>width) width=preci;
	goto num_printf;
      case 'd':
      case 'i':
	flag_in_sign=1;
      case 'u':
	base=10;
	sz=0;
	goto num_printf;
      case 'o':
	base=8;
	sz=0;
	if (flag_hash) {
	  buf[1]='0';
	  flag_hash=1;
	  ++sz;
	}

num_printf:
	s=buf+1;

	if (flag_long>0) {
#ifdef WANT_LONGLONG_PRINTF
	  if (flag_long>1)
	    llnumber=va_arg(arg_ptr,long long);
	  else
#endif
	    number=va_arg(arg_ptr,long);
	}
	else
	  number=va_arg(arg_ptr,int);

	if (flag_in_sign) {
#ifdef WANT_LONGLONG_PRINTF
	  if ((flag_long>1)&&(llnumber<0)) {
	    llnumber=-llnumber;
	    flag_in_sign=2;
	  } else
#endif
	    if (number<0) {
	      number=-number;
	      flag_in_sign=2;
	    }
	}
	if (flag_long<0) number&=0xffff;
	if (flag_long<-1) number&=0xff;
#ifdef WANT_LONGLONG_PRINTF
	if (flag_long>1)
	  retval = __lltostr(s+sz,sizeof(buf)-5,(unsigned long long) llnumber,base,flag_upcase);
	else
#endif
	  retval = __ltostr(s+sz,sizeof(buf)-5,(unsigned long) number,base,flag_upcase);

	/* When 0 is printed with an explicit precision 0, the output is empty. */
	if (flag_dot && retval == 1 && s[sz] == '0') {
	  if (preci == 0||flag_hash > 0) {
	    sz = 0;
	  }
	  flag_hash = 0;
	} else sz += retval;

	if (flag_in_sign==2) {
	  *(--s)='-';
	  ++sz;
	} else if ((flag_in_sign)&&(flag_sign || flag_space)) {
	  *(--s)=(flag_sign)?'+':' ';
	  ++sz;
	} else flag_in_sign=0;

	goto print_out;

#ifdef WANT_FLOATING_POINT_IN_PRINTF
      /* print a floating point value */
      case 'f':
      case 'g':
	{
	  int g=(ch=='g');
	  double d=va_arg(arg_ptr,double);
	  s=buf+1;
	  if (width==0) width=1;
	  if (!flag_dot) preci=6;
	  if (flag_sign || d < +0.0) flag_in_sign=1;
	  
	  sz=__dtostr(d,s,sizeof(buf)-1,width,preci);
	  
	  if (flag_dot) {
	    char *tmp;
	    if ((tmp=strchr(s,'.'))) {
	      if (preci || flag_hash) ++tmp;
	      while (preci>0 && *++tmp) --preci;
	      *tmp=0;
	    } else if (flag_hash) {
	      s[sz]='.';
	      s[++sz]='\0';
	    }
	  }

	  if (g) {
	    char *tmp,*tmp1;	/* boy, is _this_ ugly! */
	    if ((tmp=strchr(s,'.'))) {
	      tmp1=strchr(tmp,'e');
	      while (*tmp) ++tmp;
	      if (tmp1) tmp=tmp1;
	      while (*--tmp=='0') ;
	      if (*tmp!='.') ++tmp;
	      *tmp=0;
	      if (tmp1) strcpy(tmp,tmp1);
	    }
	  }
	  
	  if ((flag_sign || flag_space) && d>=0) {
	    *(--s)=(flag_sign)?'+':' ';
	    ++sz;
	  }
	  
	  sz=strlen(s);
	  flag_dot=0;
	  flag_hash=0;
	  goto print_out;
	}
#endif

      default:
	break;
      }
    }
  }
  return len;
}

#undef s

static int swrite(void*ptr, size_t nmemb, struct str_data* sd) {
  size_t tmp=sd->size-sd->len;
  if (tmp>0) {
    size_t len=nmemb;
    if (len>tmp) len=tmp;
    if (sd->str) {
      memcpy(sd->str+sd->len,ptr,len);
      sd->str[sd->len+len]=0;
    }
    sd->len+=len;
  }
  return nmemb;
}

int _win_vsnprintf(char* str, size_t size, const char *format, va_list arg_ptr)
{
  long n;
  struct str_data sd = { str, 0, size?size-1:0 };
  struct arg_printf ap = { &sd, (int(*)(void*,size_t,void*)) swrite };
  n=__v_printf(&ap,format,arg_ptr);
  if (str && size && n>=0) {
    if (size!=(size_t)-1 && ((size_t)n>=size)) str[size-1]=0;
    else str[n]=0;
  }
  return n;
}

int _win_vsprintf(char *dest, const char *format, va_list arg_ptr)
{
  return _win_vsnprintf(dest,(size_t)-1,format,arg_ptr);
}

static int __fwrite(void*ptr, size_t nmemb, int fd) {
  return fwrite(ptr, 1, nmemb, fd);
}

int _win_vfprintf(FILE *stream, const char *format, va_list arg_ptr)
{
  struct arg_printf ap = { stream, (int(*)(void*,size_t,void*)) __fwrite };
  return __v_printf(&ap,format,arg_ptr);
}

int __stdio_outs(const char *s, size_t len) {
  return (fwrite(s, 1, len, stdout)==(int)len)?1:0;
}

int _win_vprintf(const char *format, va_list ap)
{
  struct arg_printf _ap = { 0, (int(*)(void*,size_t,void*)) __stdio_outs };
  return __v_printf(&_ap,format,ap);
}

int _win_fprintf(FILE *f,const char *format, ...)
{
  int n;
  va_list arg_ptr;
  va_start(arg_ptr,format);
  n=_win_vfprintf(f,format,arg_ptr);
  va_end(arg_ptr);
  return n;
}

int _win_printf(const char *format, ...)
{
  int n;
  va_list arg_ptr;
  va_start(arg_ptr, format);
  n=_win_vprintf(format, arg_ptr);
  va_end(arg_ptr);
  return n;
}

int _win_snprintf(char *str, size_t size, const char *format, ...)
{
  int n;
  va_list arg_ptr;
  va_start(arg_ptr, format);
  n=vsnprintf(str,size,format,arg_ptr);
  va_end (arg_ptr);
  return n;
}

int _win_sprintf(char *dest, const char *format, ...)
{
  int n;
  va_list arg_ptr;
  va_start(arg_ptr, format);
  n=vsprintf(dest,format,arg_ptr);
  va_end (arg_ptr);
  return n;
}

#define A_GETC(fn)  (++consumed,(fn)->getch((fn)->data))
#define A_PUTC(c,fn)  (--consumed,(fn)->putch((c),(fn)->data))

struct arg_scanf {
  void *data;
  int (*getch)(void*);
  int (*putch)(int,void*);
};

int __v_scanf(struct arg_scanf* fn, const unsigned char *format, va_list arg_ptr)
{
  unsigned int ch;  /* format act. char */
  int n=0;

  /* arg_ptr tmps */
#ifdef WANT_FLOATING_POINT_IN_SCANF
  double *pd;
  float  *pf;
#endif
#ifdef WANT_LONGLONG_SCANF
  long long *pll;
#endif
  long   *pl;
  short  *ph;
  int    *pi;
  char    *s;

  unsigned int consumed=0;

  /* get one char */
  int tpch= A_GETC(fn);

  //while ((tpch!=-1)&&(*format))
  while (*format)
  {
    ch=*format++;
    switch (ch) {
    /* end of format string ?!? */
    case 0: return 0;

    /* skip spaces ... */
    case ' ':
    case '\f':
    case '\t':
    case '\v':
    case '\n':
    case '\r':
      while((*format)&&(isspace(*format))) ++format;
      while(isspace(tpch)) tpch=A_GETC(fn);
      break;

    /* format string ... */
    case '%':
      {
  unsigned int _div=0;
  int width=-1;
  char flag_width=0;
  char flag_discard=0;
  char flag_half=0;
  char flag_long=0;
  char flag_longlong=0;

in_scan:
  ch=*format++;
  if(ch!='n' && tpch==-1) goto err_out;
  switch (ch) {
  /* end of format string ?!? */
  case 0: return 0;

  /* check for % */
  case '%':
    if ((unsigned char)tpch != ch) goto err_out;
    tpch=A_GETC(fn);
    break;

  /* FLAGS */
  case '*':
    flag_discard=1;
    goto in_scan;
  case 'h':
    flag_half=1;
    goto in_scan;
  case 'l':
    if (flag_long) flag_longlong=1;
    flag_long=1;
    goto in_scan;
  case 'q':
  case 'L':
    flag_longlong=1;
    goto in_scan;

  /* WIDTH */
  case '0':
  case '1':
  case '2':
  case '3':
  case '4':
  case '5':
  case '6':
  case '7':
  case '8':
  case '9':
    width=strtol(format-1,&s,10);
    format=s;
    flag_width=1;
    goto in_scan;

  /* scan for integer / strtol reimplementation ... */
  case 'p':
  case 'X':
  case 'x':
    _div+=6;
  case 'd':
    _div+=2;
  case 'o':
    _div+=8;
  case 'u':
  case 'i':
    {
#ifdef WANT_LONGLONG_SCANF
      unsigned long long v=0;
#else
      unsigned long v=0;
#endif
      unsigned int consumedsofar;
      int neg=0;
      while(isspace(tpch)) tpch=A_GETC(fn);
      if (tpch=='-') {
        tpch=A_GETC(fn);
        neg=1;
      }

      if (tpch=='+') tpch=A_GETC(fn);

      if (tpch==-1) return n;
      consumedsofar=consumed;

      if (!flag_width) {
        if ((_div==16) && (tpch=='0')) goto scan_hex;
        if (!_div) {
    _div=10;
    if (tpch=='0') {
      _div=8;
scan_hex:
      tpch=A_GETC(fn);
      if ((tpch|32)=='x') {
        tpch=A_GETC(fn);
        _div=16;
      }
    }
        }
      }
      while ((width)&&(tpch!=-1)) {
        register unsigned long c=tpch&0xff;
#ifdef WANT_LONGLONG_SCANF
        register unsigned long long d=c|0x20;
#else
        register unsigned long d=c|0x20;
#endif
        c=(d>='a'?d-'a'+10:c<='9'?c-'0':0xff);
        if (c>=_div) break;
        d=v*_div;
#ifdef WANT_LONGLONG_SCANF
        v=(d<v)?ULLONG_MAX:d+c;
#else
        v=(d<v)?ULONG_MAX:d+c;
#endif
        --width;
        tpch=A_GETC(fn);
      }

      if (consumedsofar==consumed) return n;

      if ((ch|0x20)<'p') {
#ifdef WANT_LONGLONG_SCANF
        register long long l=v;
        if (v>=-((unsigned long long)LLONG_MIN)) {
    l=(neg)?LLONG_MIN:LLONG_MAX;
        }
        else {
    if (neg) v*=-1;
        }
#else
        register long l=v;
        if (v>=-((unsigned long)LONG_MIN)) {
    l=(neg)?LONG_MIN:LONG_MAX;
        }
        else {
    if (neg) v*=-1;
        }
#endif
      }
      if (!flag_discard) {
#ifdef WANT_LONGLONG_SCANF
        if (flag_longlong) {
    pll=(long long *)va_arg(arg_ptr,long long*);
    *pll=v;
        } else
#endif
        if (flag_long) {
    pl=(long *)va_arg(arg_ptr,long*);
    *pl=v;
        } else if (flag_half) {
    ph=(short*)va_arg(arg_ptr,short*);
    *ph=v;
        } else {
    pi=(int *)va_arg(arg_ptr,int*);
    *pi=v;
        }
        if(consumedsofar<consumed) ++n;
      }
    }
    break;

  /* FIXME: return value of *scanf with ONE float maybe -1 instead of 0 */
#ifdef WANT_FLOATING_POINT_IN_SCANF
  /* floating point numbers */
  case 'e':
  case 'E':
  case 'f':
  case 'g':
    {
      double d=0.0;
      int neg=0;
      unsigned int consumedsofar;

      while(isspace(tpch)) tpch=A_GETC(fn);

      if (tpch=='-') {
        tpch=A_GETC(fn);
        neg=1;
      }
      if (tpch=='+') tpch=A_GETC(fn);

      consumedsofar=consumed;

      while (isdigit(tpch)) {
        d=d*10+(tpch-'0');
        tpch=A_GETC(fn);
      }
      if (tpch=='.') {
        double factor=.1;
        consumedsofar++;
        tpch=A_GETC(fn);
        while (isdigit(tpch)) {
    d=d+(factor*(tpch-'0'));
    factor/=10;
    tpch=A_GETC(fn);
        }
      }
      if (consumedsofar==consumed) return n;  /* error */
      if ((tpch|0x20)=='e') {
        int exp=0, prec=tpch;
        double factor=10;
        tpch=A_GETC(fn);
        if (tpch=='-') {
    factor=0.1;
    tpch=A_GETC(fn);
        } else if (tpch=='+') {
    tpch=A_GETC(fn);
        } else {
    d=0;
    if (tpch!=-1) A_PUTC(tpch,fn);
    tpch=prec;
    goto exp_out;
        }
        consumedsofar=consumed;
        while (isdigit(tpch)) {
    exp=exp*10+(tpch-'0');
    tpch=A_GETC(fn);
        }
        if (consumedsofar==consumed) return n;  /* error */
        while (exp) { /* as in strtod: XXX: this introduces rounding errors */
    d*=factor; --exp;
        }
      }
exp_out:
      if (!flag_discard) {
        if (flag_long) {
    pd=(double *)va_arg(arg_ptr,double*);
    *pd=d;
        } else {
    pf=(float *)va_arg(arg_ptr,float*);
    *pf=d;
        }
        ++n;
      }
    }
    break;
#endif

  /* char-sequences */
  case 'c':
    if (!flag_discard) {
      s=(char *)va_arg(arg_ptr,char*);
      ++n;
    }
    if (!flag_width) width=1;
    while (width && (tpch!=-1)) {
      if (!flag_discard) *(s++)=tpch;
      --width;
      tpch=A_GETC(fn);
    }
    break;

  /* string */
  case 's':
    if (!flag_discard) s=(char *)va_arg(arg_ptr,char*);
    while(isspace(tpch)) tpch=A_GETC(fn);
    if (tpch==-1) break;    /* end of scan -> error */
    while (width && (tpch!=-1) && (!isspace(tpch))) {
      if (!flag_discard) *s=tpch;
      if (tpch) ++s; else break;
      --width;
      tpch=A_GETC(fn);
    }
    if (!flag_discard) { *s=0; ++n; }
    break;

  /* consumed-count */
  case 'n':
    if (!flag_discard) {
      pi=(int *)va_arg(arg_ptr,int *);
//      ++n;  /* in accordance to ANSI C we don't count this conversion */
            *pi=consumed-1;
    }
    break;

#ifdef WANT_CHARACTER_CLASSES_IN_SCANF
  case '[':
    {
      char cset[256];
      int flag_not=0;
      int flag_dash=0;
      memset(cset,0,sizeof(cset));
      ch=*format++;
      /* first char specials */
      if (ch=='^') {
        flag_not=1;
        ch=*format++;
      }
      if ((ch=='-')||(ch==']')) {
        cset[ch]=1;
        ch=*format++;
      }
      /* almost all non special chars */
      for (;(*format) && (*format!=']');++format) {
        if (flag_dash) {
    register unsigned char tmp=*format;
    for (;ch<=tmp;++ch) cset[ch]=1;
    flag_dash=0;
    ch=*format;
        }
        else if (*format=='-') flag_dash=1;
        else {
    cset[ch]=1;
    ch=*format;
        }
      }
      /* last char specials */
      if (flag_dash) cset['-']=1;
      else cset[ch]=1;

      /* like %c or %s */
      if (!flag_discard) {
        s=(char *)va_arg(arg_ptr,char*);
        ++n;
      }
      while (width && (tpch>=0) && (cset[tpch]^flag_not)) {
        if (!flag_discard) *s=tpch;
        if (tpch) ++s; else break;
        --width;
        tpch=A_GETC(fn);
      }
      if (!flag_discard) *s=0;
      ++format;
    }
    break;
#endif
  default:
    goto err_out;
  }
      }
      break;

    /* check if equal format string... */
    default:
      if ((unsigned char)tpch != ch) goto err_out;
      tpch=A_GETC(fn);
      break;
    }
  }

  /* maybe a "%n" follows */
  if(*format) {
    while(isspace(*format)) format++;
    if(format[0] == '%' && format[1] == 'n') {
      pi = (int *) va_arg(arg_ptr, int *);
      *pi = consumed - 1;
    }
  }

err_out:
  if (tpch<0 && n==0) return EOF;
  A_PUTC(tpch,fn);
  return n;
}

struct scanf_str_data {
  unsigned char* str;
};

static int sgetc(struct scanf_str_data* sd) {
  register unsigned int ret = *(sd->str++);
  return (ret)?(int)ret:-1;
}

static int sputc(int c, struct scanf_str_data* sd) {
  return (*(--sd->str)==c)?c:-1;
}

int _win_vsscanf(const char* str, const char* format, va_list arg_ptr)
{
  struct scanf_str_data  fdat = { (unsigned char*)str };
  struct arg_scanf farg = { (void*)&fdat, (int(*)(void*))sgetc, (int(*)(int,void*))sputc };
  return __v_scanf(&farg,format,arg_ptr);
}

int _win_sscanf(const char *str, const char *format, ...)
{
  int n;
  va_list arg_ptr;
  va_start(arg_ptr, format);
  n = _win_vsscanf(str,format,arg_ptr);
  va_end (arg_ptr);
  return n;
}

int _win_vfscanf(FILE *stream, const char *format, va_list arg_ptr)
{
  struct arg_scanf farg = { (void*)stream, (int(*)(void*))fgetc, (int(*)(int,void*))ungetc };
  return __v_scanf(&farg,format,arg_ptr);
}

int _win_vscanf(const char *format, va_list arg_ptr)
{
  return _win_vfscanf(stdin,format,arg_ptr);
}

int _win_scanf(const char *format, ...)
{
  int n;
  va_list arg_ptr;
  va_start(arg_ptr, format);
  n = _win_vfscanf(stdin,format,arg_ptr);
  va_end (arg_ptr);
  return n;
}

int _win_fscanf(FILE *stream, const char *format, ...)
{
  int n;
  va_list arg_ptr;
  va_start(arg_ptr, format);
  n = _win_vfscanf(stream,format,arg_ptr);
  va_end (arg_ptr);
  return n;
}

/* end of win_printf.c */
