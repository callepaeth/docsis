/* vim: expandtab sw=3 */
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <errno.h>

#include "docsis.h"
#include "docsis_globals.h"
#include "docsis_common.h"
#include "docsis_decode.h"
#include "docsis_encode.h"

struct typemap {
   char *name;
   encode_func_t encode_func;
   decode_func_t decode_func;
} typemap[] = {
   { "special", encode_nothing, decode_special },
   { "md5", encode_nothing, decode_md5 },
   { "aggregate", encode_nothing, decode_aggregate },
   { "snmp_object", encode_nothing, decode_snmp_object },
   { "snmp_wd", encode_nothing, decode_snmp_wd },
   { "vspecific", encode_nothing, decode_vspecific },
   { "uchar", encode_uchar, decode_uchar },
   { "char_list", encode_char_list, decode_char_list },
   { "ushort", encode_ushort, decode_ushort },
   { "ushort_list", encode_ushort_list, decode_ushort_list },
   { "uint", encode_uint, decode_uint },
   { "uint24", encode_uint24, decode_uint24 },
   { "hexstr", encode_hexstr, decode_hexstr },
   { "hexstr_nothing", encode_nothing, decode_hexstr },
   { "string", encode_string, decode_string },
   { "strzero", encode_strzero, decode_strzero },
   { "ip", encode_ip, decode_ip },
   { "ip_list", encode_ip_list, decode_ip_list },
   { "ip6", encode_ip6, decode_ip6 },
   { "ip6_list", encode_ip6_list, decode_ip6_list },
   { "ip_ip6", encode_ip_ip6, decode_ip_ip6 },
   { "char_ip_ip6", encode_char_ip_ip6, decode_char_ip_ip6 },
   { "ip_ip6_port", encode_ip_ip6_port, decode_ip_ip6_port },
   { "ip6_prefix_list", encode_ip6_prefix_list, decode_ip6_prefix_list },
   { "dual_qtag", encode_dual_qtag, decode_dual_qtag },
   { "ethermask", encode_ethermask, decode_ethermask },
   { "ether", encode_ether, decode_ether },
   { "oid", encode_oid, decode_oid },
   { "lenzero", encode_lenzero, decode_lenzero },
   { "unknown", encode_hexstr, decode_hexstr },
   { 0, 0, 0 },
};

/* ------------------------------------------------------------------- */

#define TLVID_MAX	32

struct tlvid {
   unsigned long code[TLVID_MAX];
   int len;
};

struct entry {
   struct entry *next;
   struct tlvid tid;
   char *name;
   struct typemap *tp;
   unsigned int low;
   unsigned int high;
   /* */
   struct entry *children;
   unsigned id;
   unsigned long docsis_code;
   unsigned parentid;
};

/* ------------------------------------------------------------------- */

static void output_tlvid(FILE *fp, struct tlvid *tid)
{
   int i;
   for (i=0; i < tid->len; i++) {
      if (tid->code[i] & DOCSIS_OID_BIT) {
         fprintf(fp, "%s0x%02lX%02lX%02lX", i ? "." : "",
	             (tid->code[i] >> 16) & 0xff,
	             (tid->code[i] >> 8) & 0xff,
	             (tid->code[i]) & 0xff);
      } else {
         fprintf(fp, "%s%lu", i ? "." : "", tid->code[i]);
      }
   }
}


static void output_entries(FILE *fp, struct entry *ep, int level);

static void output_entry(FILE *fp, struct entry *ep, int level)
{
    struct entry *child;

    if (ep->docsis_code & DOCSIS_OID_BIT) {
       fprintf(fp, "%4u %4u 0x%6lX %-40s",
    		   ep->id,
		   ep->parentid,
		   ep->docsis_code & 0xffffff,
		   ep->name);
    } else {
       fprintf(fp, "%4u %4u %8lu %-40s",
    		   ep->id,
		   ep->parentid,
		   ep->docsis_code,
		   ep->name);
    }
    fprintf(fp, " TLV ");
    output_tlvid(fp, &ep->tid);
    fprintf(fp, "\n");

    for (child = ep->children; child; child = child->next) {
       output_entry(fp, child, level+1);
    }
}

static void output_entries(FILE *fp, struct entry *ep, int level)
{
    for (; ep; ep = ep->next)
       output_entry(fp, ep, level);
}

/* ------------------------------------------------------------------- */

typedef void (*entry_mapfunc_t)(struct entry*, int, void *);

static void map_entry(struct entry *ep, int level,
                      entry_mapfunc_t mapfunc, void *arg)
{
    struct entry *child;
    if (mapfunc)
       (*mapfunc)(ep, level, arg);
    for (child = ep->children; child; child = child->next) {
       map_entry(child, level+1, mapfunc, arg);
    }
}

static void map_entries(struct entry *ep, int level,
                        entry_mapfunc_t mapfunc, void *arg)
{
    for (; ep; ep = ep->next)
       map_entry(ep, level, mapfunc, arg);
}

/* ------------------------------------------------------------------- */

static void count_entry(struct entry *ep, int level, void *arg)
{
    unsigned *countp = (unsigned *)arg;
    (*countp)++;
}

static unsigned count_entries(struct entry *ep)
{
   unsigned count = 0;
   map_entries(ep, 0, count_entry, (void *)&count);
   return count;
}

/* ------------------------------------------------------------------- */

static void fill_symtable(symbol_type *p, struct entry *ep)
{
    memset(p, 0, sizeof(symbol_type));
    p->id = ep->id;
    snprintf(p->sym_ident, sizeof(p->sym_ident), "%s", ep->name);
    p->docsis_code = ep->docsis_code;
    p->parent_id = ep->parentid;
    p->encode_func = ep->tp->encode_func;
    p->decode_func = ep->tp->decode_func;
    p->low_limit = ep->low;
    p->high_limit = ep->high;
}

static void fill_entry(struct entry *ep, int level, void *arg)
{
    unsigned *offsetp = (unsigned *)arg;
    fill_symtable(&global_symtable[(*offsetp)++], ep);
}

static void init_global_symtable(struct entry *ep)
{
   unsigned offset = 0;
   global_symtable_nsyms = count_entries(ep);

   global_symtable = (symbol_type *)calloc(global_symtable_nsyms, sizeof(symbol_type));
   map_entries(ep, 0, fill_entry, (void *)&offset);
}

/* ------------------------------------------------------------------- */

static unsigned long set_ids(unsigned long nextid, struct entry *ep);

static unsigned long set_id(unsigned long nextid, struct entry *ep)
{
    struct entry *child;
    ep->id = nextid++;
    for (child = ep->children; child; child = child->next) {
       child->parentid = ep->id;
       nextid = set_id(nextid, child);
    }
    return nextid;
}

static unsigned long int set_ids(unsigned long nextid, struct entry *ep)
{
    for (; ep; ep = ep->next)
       nextid = set_id(nextid, ep);
    return nextid;
}

/* ------------------------------------------------------------------- */

static struct typemap *find_type(char *name)
{
   struct typemap *tp;
   for (tp = typemap; tp->name; tp++) {
      if (strcmp(name, tp->name) == 0)
         return tp;

   }
   return 0;
}

/* ------------------------------------------------------------------- */

static int parse_tlvid(char *str, char **pp, struct tlvid *tid)
{
   char *s;

   tid->len = 0;
   s = str;
   while (*s && tid->len < TLVID_MAX-1) {
      char *tmp = s;
      if (strncmp(s, "0x", 2) == 0) {
         if (tid->len == 0 || tid->code[tid->len-1] != 43)
            goto error;
         tid->code[tid->len] = strtol(s, &tmp, 16);
	 tid->code[tid->len] |= DOCSIS_OID_BIT;
      } else {
         tid->code[tid->len] = strtol(s, &tmp, 10);
      }
      if (tmp == s)
         goto error;
      tid->len++;
      s = tmp;
      if (*s) {
         if (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        break;
     if (*s != '.')
        goto error;
         s++;
      }
   }
   *pp = s;
   return 0;
error:
   *pp = str;
   return -1;
}

static char *skip_space(char *str)
{
   while (*str == ' ' || *str == '\t') str++;
   return str;
}

static char *skip_nonspace(char *str)
{
   while (*str && *str != ' ' && *str != '\t' && *str != '\r' && *str != '\n')
      str++;
   return str;
}

static struct entry *list = 0;

static int add_entry(struct tlvid *tid, char *name, struct typemap *tp,
                     unsigned int low, unsigned int high)
{
   struct entry *ep, *p, **pp;
   int i;

   if ((ep = (struct entry *)malloc(sizeof(struct entry))) == 0)
      return 0;
   memset(ep, 0 , sizeof(struct entry));
   ep->tid = *tid;
   if ((ep->name = strdup(name)) == 0) {
      free(ep);
      return 0;
   }
   ep->tp = tp;
   ep->low = low;
   ep->high = high;
   ep->docsis_code = tid->code[tid->len-1];

   pp = &list;
   for (i = 0; i < tid->len; i++) {
      while ((p = *pp) != 0 && p->docsis_code < tid->code[i])
         pp = &(*pp)->next;
      if (p && p->docsis_code == tid->code[i]) {
         if (i+1 < tid->len) {
            pp = &p->children;
            continue;
         }
         if (strcmp(p->name, ep->name) == 0)  {
            /* overwrite type and range */
            p->tp = tp;
            p->low = low;
            p->high = high;
            free(ep);
            return 0;
         }
         /* append alias */
         pp = &(*pp)->next;
      }
      ep->next = *pp;
      *pp = ep;
      return 0;
   }
   free(ep);
   return -1;
}

/*1	DownstreamFrequency	uint		88000000	860000000*/

int parsedef_loadfile(const char *fn, int optional)
{
   int errcount = 0;
   int line = 0;
   char buf[4096];
   FILE *infp;

   if ((infp = fopen(fn, "r")) == 0) {
      if (optional && errno == ENOENT)
         return 0;
      fprintf(stderr, "%s: ", fn);
      perror("open");
      return -1;
   }
   while (fgets(buf, sizeof(buf), infp)) {
      struct typemap *tp;
      struct tlvid tid;
      char *tlv, *name, *type, *s;
      unsigned int low = 0, high = 0;

      line++;
      tlv = skip_space(buf);
      if (*tlv == '\r' || *tlv == '\n' || *tlv == '#') continue;
      name = tlv;
      if (parse_tlvid(tlv, &name, &tid) < 0) {
         fprintf(stderr, "%s:%d: Can't parse tivid\n", fn , line);
         errcount++;
         continue;
      }
      name = skip_space(name);
      s = skip_nonspace(name);
      if (*s == 0) {
         fprintf(stderr, "%s:%d: no name found\n", fn , line);
         errcount++;
         continue;
      }
      *s++ = 0;
      type = skip_space(s);
      s = skip_nonspace(type);
      if (*s == 0) {
         fprintf(stderr, "%s:%d: no type found\n", fn , line);
         errcount++;
         continue;
      }
      *s++ = 0;
      if ((tp = find_type(type)) == 0) {
         fprintf(stderr, "%s:%d: type %s not found\n", fn , line, type);
         errcount++;
         continue;
      }
      s = skip_space(s);
      if (*s && *s != '\r' && *s != '\n') {
         char *tmp = s;
         low = strtoul(s, &tmp, 0);
         if (s == tmp) {
            fprintf(stderr, "%s:%d: illegal low value\n", fn , line);
            errcount++;
            continue;
         }
         s = skip_space(tmp);
         high = strtoul(s, &tmp, 0);
         if (s == tmp) {
            fprintf(stderr, "%s:%d: illegal high value\n", fn , line);
            errcount++;
            continue;
         }
         s = skip_space(tmp);
      }
      if (*s && *s != '\r' && *s != '\n')
         fprintf(stderr, "%s:%d: extra characters ignored\n", fn , line);
      (void)add_entry(&tid, name, tp, low, high);
   }
   fclose(infp);
   return errcount;
}

int parsedef_finish(int show)
{
   set_ids(0, list);
   init_global_symtable(list);
   if (show)
      output_entries(stdout, list, 0);
   return 0;
}
