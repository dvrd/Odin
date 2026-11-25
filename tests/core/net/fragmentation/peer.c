/* Independent kernel/packet probe; never links Odin networking implementation. */
#define __APPLE_USE_RFC_3542 1
#define _DEFAULT_SOURCE 1
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <net/if.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#endif
#define REQUIRE(x) do {if (!(x)) {fprintf(stderr,"failed %s errno=%d\n",#x,errno);exit(1);}} while(0)
static int get(int fd,int level,int option) {int v=-99;socklen_t n=sizeof(v);REQUIRE(getsockopt(fd,level,option,&v,&n)==0&&n==sizeof(v));return v;}
static void set(int fd,int level,int option,int value) {REQUIRE(setsockopt(fd,level,option,&value,sizeof(value))==0);}
static void options(void) {
 for(int family_index=0;family_index<2;family_index++) {
  int family=family_index?AF_INET6:AF_INET;int fd=socket(family,SOCK_DGRAM,0);REQUIRE(fd>=0);
#ifdef __linux__
  int level=family_index?IPPROTO_IPV6:IPPROTO_IP,option=family_index?IPV6_MTU_DISCOVER:IP_MTU_DISCOVER,expected=IP_PMTUDISC_DO;
#else
  int level=family_index?IPPROTO_IPV6:IPPROTO_IP,option=family_index?IPV6_DONTFRAG:IP_DONTFRAG,expected=1;
#endif
  int before=get(fd,level,option);set(fd,level,option,expected);REQUIRE(get(fd,level,option)==expected);
  int dual=family_index?get(fd,IPPROTO_IPV6,IPV6_V6ONLY)==0:0;
#ifdef __linux__
  if(dual) {set(fd,IPPROTO_IP,IP_MTU_DISCOVER,IP_PMTUDISC_DO);REQUIRE(get(fd,IPPROTO_IP,IP_MTU_DISCOVER)==IP_PMTUDISC_DO);}
#endif
  printf("{\"independent_kernel\":\"%s\",\"before\":%d,\"configured\":%d,\"dual_stack\":%s}\n",family_index?"ipv6":"ipv4",before,expected,dual?"true":"false");close(fd);
 }
}
#ifdef __linux__
static uint16_t read16(const unsigned char *p) {return ((uint16_t)p[0]<<8)|p[1];}
#endif
static void send_to_native_mapped_receiver(const char *binary) {
 int channel[2];REQUIRE(pipe(channel)==0);fflush(stdout);pid_t child=fork();REQUIRE(child>=0);
 if(child==0) {close(channel[0]);REQUIRE(dup2(channel[1],STDOUT_FILENO)>=0);close(channel[1]);execl(binary,binary,"receive-mapped","0",(char*)0);_exit(127);}
 close(channel[1]);FILE *stream=fdopen(channel[0],"r");REQUIRE(stream!=NULL);char line[1024];REQUIRE(fgets(line,sizeof(line),stream)!=NULL);unsigned port=0;REQUIRE(sscanf(line,"READY %u",&port)==1&&port>0);
 int sender=socket(AF_INET,SOCK_DGRAM,0);REQUIRE(sender>=0);set(sender,IPPROTO_IP,IP_TOS,3);
 struct sockaddr_in target;memset(&target,0,sizeof(target));target.sin_family=AF_INET;target.sin_addr.s_addr=htonl(INADDR_LOOPBACK);target.sin_port=htons(port);
 unsigned char body[1200];for(int i=0;i<1200;i++)body[i]=(unsigned char)(i%251);memcpy(body,"webtools400",11);
 REQUIRE(sendto(sender,body,sizeof(body),0,(void*)&target,sizeof(target))==1200);close(sender);
 REQUIRE(fgets(line,sizeof(line),stream)!=NULL&&strstr(line,"\"ecn\":3")!=NULL&&strstr(line,"\"received\":1200")!=NULL);fputs(line,stdout);fclose(stream);
 int status=0;REQUIRE(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
 printf("{\"independent_sender\":\"ipv4\",\"native_receiver\":\"dual-stack-mapped\",\"ecn\":3,\"received\":1200}\n");
}
int main(int argc,char **argv) {
 REQUIRE(argc==3);options();
 if(strcmp(argv[2],"receive-mapped")==0) {send_to_native_mapped_receiver(argv[1]);return 0;}
 const char *mode=argv[2];int v6=strcmp(mode,"ipv6")==0;
 int receiver=socket(v6?AF_INET6:AF_INET,SOCK_DGRAM,0);REQUIRE(receiver>=0);
 struct sockaddr_storage local;memset(&local,0,sizeof(local));socklen_t size;
 if(v6) {struct sockaddr_in6 *a=(void*)&local;a->sin6_family=AF_INET6;a->sin6_addr=in6addr_loopback;size=sizeof(*a);}
 else {struct sockaddr_in *a=(void*)&local;a->sin_family=AF_INET;a->sin_addr.s_addr=htonl(INADDR_LOOPBACK);size=sizeof(*a);}
 REQUIRE(bind(receiver,(void*)&local,size)==0);REQUIRE(getsockname(receiver,(void*)&local,&size)==0);
 unsigned port=ntohs(v6?((struct sockaddr_in6*)&local)->sin6_port:((struct sockaddr_in*)&local)->sin_port);
 struct timeval timeout={3,0};REQUIRE(setsockopt(receiver,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))==0);
 int capture=-1;
#ifdef __linux__
 capture=socket(AF_PACKET,SOCK_RAW|SOCK_CLOEXEC,htons(ETH_P_ALL));REQUIRE(capture>=0);
 struct sockaddr_ll link;memset(&link,0,sizeof(link));link.sll_family=AF_PACKET;link.sll_protocol=htons(ETH_P_ALL);link.sll_ifindex=if_nametoindex("lo");REQUIRE(link.sll_ifindex!=0);
 REQUIRE(bind(capture,(void*)&link,sizeof(link))==0);REQUIRE(setsockopt(capture,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))==0);
#else
 /* Raw capture needs a privileged Darwin process; preserve that explicit limit. */
 capture=socket(AF_INET,SOCK_RAW,IPPROTO_UDP);
 if(capture<0) printf("{\"wire_capture\":\"unavailable\",\"errno\":%d}\n",errno);
 if(capture>=0) close(capture);capture=-1;
#endif
 fflush(stdout);pid_t child=fork();REQUIRE(child>=0);
 if(child==0) {char port_text[16];snprintf(port_text,sizeof(port_text),"%u",port);execl(argv[1],argv[1],mode,port_text,(char*)0);_exit(127);}
 unsigned char body[1200];ssize_t n=recv(receiver,body,sizeof(body),0);REQUIRE(n==1200&&memcmp(body,"webtools400",11)==0);
 for(int i=11;i<1200;i++) REQUIRE(body[i]==(unsigned char)(i%251));
#ifdef __linux__
 int observed=0;
 for(int attempt=0;attempt<128&&!observed;attempt++) {
  unsigned char frame[4096];ssize_t count=recv(capture,frame,sizeof(frame),0);REQUIRE(count>0);
  if(count<14+20) continue;unsigned char *ip=frame+14;int version=ip[0]>>4;unsigned char *udp=NULL;int ecn=0;
  if(version==4&&read16(frame+12)==ETH_P_IP) {
   int header=(ip[0]&15)*4;if(header<20||count<14+header+8||ip[9]!=17) continue;udp=ip+header;ecn=ip[1]&3;
   if(read16(udp+2)!=port||count<14+header+8+1200||memcmp(udp+8,"webtools400",11)) continue;
   unsigned fragment=read16(ip+6);REQUIRE((fragment&0x4000)!=0&&(fragment&0x3fff)==0);REQUIRE(!v6);
  } else if(version==6&&read16(frame+12)==ETH_P_IPV6) {
   if(count<14+40+8+1200||ip[6]!=17) continue;udp=ip+40;ecn=((ip[0]&15)<<4|ip[1]>>4)&3;
   if(read16(udp+2)!=port||memcmp(udp+8,"webtools400",11)) continue;REQUIRE(v6);
  } else continue;
  if(read16(udp+4)!=1208||ecn!=3) fprintf(stderr,"observed_udp_length=%u observed_ecn=%d mode=%s\n",read16(udp+4),ecn,mode);
  REQUIRE(read16(udp+4)==1208&&ecn==3);observed=1;
 }
 REQUIRE(observed);printf("{\"wire_mode\":\"%s\",\"capture\":\"AF_PACKET\",\"unfragmented\":true,\"ipv4_df\":%s,\"ecn\":3,\"payload\":1200}\n",mode,v6?"null":"true");close(capture);
#else
 printf("{\"wire_mode\":\"%s\",\"received\":1200,\"capture\":\"not_qualified\"}\n",mode);
#endif
 int status=0;REQUIRE(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);close(receiver);return 0;
}
