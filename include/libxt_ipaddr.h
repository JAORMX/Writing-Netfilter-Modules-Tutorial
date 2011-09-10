#ifndef _LINUX_NETFILTER_LIBXT_IPADDR_H
#define _LINUX_NETFILTER_LIBXT_IPADDR_H

static void ipaddr_mt_check(unsigned int);
static void ipaddr_mt_init(struct xt_entry_match *);
static void ipaddr_mt4_save(const void *, const struct xt_entry_match *);
static void ipaddr_mt4_print(const void *, const struct xt_entry_match *, int);
static int ipaddr_mt4_parse(int, char **, int, unsigned int *, const void *, 
	struct xt_entry_match **);
static void ipaddr_mt_check(unsigned int);
static void ipaddr_mt_help(void);

#endif /* _LINUX_NETFILTER_LIBXT_IPADDR_H */
