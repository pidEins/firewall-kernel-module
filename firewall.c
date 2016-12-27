#define __KERNEL__
#define MODULE
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
static struct nf_hook_ops netfilter_ops;         
static unsigned char *ip_address = "\x14\x00\x00\x03";
static char *interface = "eth1";
unsigned int main_hook(unsigned int hooknum,
                  struct sk_buff *skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))
{
  if(strcmp(in->name,interface) == 0)
  {
		  if(!skb){ return NF_ACCEPT; }
		  struct iphdr *ip_hdr = (struct iphdr *)skb_network_header(skb);
		  if(!(ip_hdr)){ return NF_ACCEPT; }
		  if(ip_hdr->protocol == IPPROTO_ICMP)
		  {
		  	struct icmphdr *icmph;
		  	icmph = icmp_hdr(skb);
		  	if(!icmph){ return NF_ACCEPT; }
			if(icmph->type != ICMP_ECHOREPLY){ 
				printk("Dropped: Unsoliited  PingPacket\n");
				return NF_DROP; }
		  }
		  if(ip_hdr->protocol == IPPROTO_UDP)
		  {
		  	struct udphdr *udph;
		  	udph = udp_hdr(skb);
		  	if(!udph){ return NF_ACCEPT; }
		  	if(ip_hdr->daddr == *(unsigned int*)ip_address){ return NF_ACCEPT; }
			unsigned int dest_port = (unsigned int)ntohs(udph->dest);
			if(dest_port == 80){ 
				printk("Dropped: Packet trying to access port 80 of internal host\n");
				return NF_DROP; }
		  }

		  if(ip_hdr->protocol == IPPROTO_TCP)
		  {
		  	struct tcphdr *tcph;
		  	tcph = tcp_hdr(skb);
		  	if(!tcph){ return NF_ACCEPT; }
			unsigned int dest_port = (unsigned int)ntohs(tcph->dest);
			if(dest_port == 22){ 
				printk("Dropped: Packet trying to access port 22 (SSH port) of internal host\n");
				return NF_DROP; }
		  	if(ip_hdr->daddr == *(unsigned int*)ip_address){ return NF_ACCEPT; }
			if(dest_port == 80){ 
				printk("Dropped: Packet trying to access port 80 of internal host\n");
				return NF_DROP; }
		  }
  }
  return NF_ACCEPT;
}
int init_module()
{
        netfilter_ops.hook              =       main_hook;
        netfilter_ops.pf                =       PF_INET;
        netfilter_ops.hooknum           =       NF_INET_PRE_ROUTING;
        netfilter_ops.priority          =       NF_IP_PRI_FIRST;
        nf_register_hook(&netfilter_ops);
	return 0;
}
void cleanup_module() { nf_unregister_hook(&netfilter_ops); }
