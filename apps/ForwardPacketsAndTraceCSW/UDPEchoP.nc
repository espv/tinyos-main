/*
 * Copyright (c) 2008-2010 The Regents of the University  of California.
 * All rights reserved."
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the
 *   distribution.
 * - Neither the name of the copyright holders nor the names of
 *   its contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <IPDispatch.h>
#include <lib6lowpan/lib6lowpan.h>
#include <lib6lowpan/ip.h>
#include <lib6lowpan/ip.h>

#include "UDPReport.h"
#include "blip_printf.h"
#include "../../tools/tinyos/c/blip/lib6lowpan/iovec.h"
#include "../../tools/tinyos/c/blip/lib6lowpan/iovec.c"

//#include "eventframework.h"

#define REPORT_PERIOD 10L
// Turn off hardware acks. This actually causes a bunch of errors, similar to disabling acks.
// The reason seems to be how blip works. It requires hardware acks to work reliably.
// Source: google "bursts of duplicate packets" to visit a thread about blip
// With hardware acks, we can expect 0 acknowledgements.
// Alternatively, we can try to get software acks to work with blip.
#undef CC2420_HW_ACKNOWLEDGEMENTS
#define CC2420_NO_ACKNOWLEDGEMENTS
#define ALL_CONTEXTS_APP 0

// Set to 1 by radio driver. Used by mote 1.
bool udpechopsent = 1;
uint32_t curseqno = 0;
uint8_t mote2_seqno = 0;
bool do_send = 0;
int nr_sending = 0;
//bool the_main_packet = 1;
int cur_rel_packet = 0;

module UDPEchoP {
  uses {
    interface Boot;
    interface SplitControl as RadioControl;

    interface UDP as Echo;
    interface UDP as Status;

    interface Leds;

    interface Timer<TMilli> as StatusTimer;

    interface BlipStatistics<ip_statistics_t> as IPStats;
    interface BlipStatistics<udp_statistics_t> as UDPStats;

    interface Random;

    interface ForwardingTable;

    interface EventFramework;

    interface Counter<TMicro, uint32_t> as AccurateTimer;

    interface Counter<TMilli, uint32_t> as MillisecondTimer;

    interface BusyWait<TMicro, uint32_t> as BusyWait;
    
    interface QuickSend;
  }

} implementation {

  bool timerStarted;
  nx_struct udp_report stats;
  struct sockaddr_in6 route_dest;
  
  bool timerToggle = 0;

  int printf_ieee154addr(ieee154_addr_t *in) {
    int i;
    switch (in->ieee_mode) {
    case IEEE154_ADDR_SHORT:
      printf("IEEE154_ADDR_SHORT: 0x%x", in->i_saddr);
      break;
    case IEEE154_ADDR_EXT:
      printf("IEEE154_ADDR_EXT: ");

      for (i = 7; i >= 0; i--) {
        printf("%02x", in->i_laddr.data[i]);
        if (i > 0)
          printf(":");
      }
      break;
    }
    return 0;
  }

  // Used for experiment to test that the timer is binary in Cooja and real life.
  /*task void afterBoot() {
    printf("\n");
    call BusyWait.wait(105000);
    printf("\n");
  }*/

  event void Boot.booted() {
    struct in6_addr next_hop;
    uint8_t prefix[8];
    call RadioControl.start();
    timerStarted = 0;

    call IPStats.clear();

    // Espen
    if (TOS_NODE_ID == 3) {
      goto after;
    } else if (TOS_NODE_ID == 2) {
      memset(&next_hop, 0, sizeof(struct in6_addr));
      next_hop.s6_addr[0] = 0xfe;
      next_hop.s6_addr[1] = 0x80;
      next_hop.s6_addr[15] = 3;
      call ForwardingTable.addRoute(NULL, 0, &next_hop, 1);
      timerToggle = 1;
      goto after;
    }

#ifdef REPORT_DEST
    route_dest.sin6_port = htons(7000);
    inet_pton6(REPORT_DEST, &route_dest.sin6_addr);
    call StatusTimer.startOneShot(1000);
#endif

after:
    dbg("Boot", "booted: %i\n", TOS_NODE_ID);
    call Echo.bind(7);
    call Status.bind(7001);
    /*{
      uint8_t i = 0;
      while (1) {
        if (i == 255)
          i = 0;
        call EventFramework.trace_event(i++);
      }
    }*/
  }

  async event void AccurateTimer.overflow() {}

  async event void MillisecondTimer.overflow() {}

  event void RadioControl.startDone(error_t e) {
  }

  event void RadioControl.stopDone(error_t e) {

  }

  event void Status.recvfrom(struct sockaddr_in6 *from, void *data,
                             uint16_t len, struct ip6_metadata *meta) {

  }

  event void Echo.recvfrom(struct sockaddr_in6 *from, void *data,
                           uint16_t len, struct ip6_metadata *meta) {
#ifdef PRINTFUART_ENABLED
    int i;
    uint8_t *cur = data;
    //printf("Echo recv [%i]: ", len);
    //for (i = 0; i < len; i++) {
    //  printf("%02x ", cur[i]);
    //}
    //printf("\n");
#endif
    //call Echo.sendto(from, data, len);
    call Leds.led0Toggle();
  }

  // Microseconds in TinyOS are in binary. 12058,624 is equal to 11500 microseconds.
  // However, we have to adjust our timer down anyway, because calculating the waiting
  // time, which is an easy arithmetic expression, takes around 200 microseconds.
  // Used for Cooja since a microsecond is 4 cycles.
  // This works currently. Remember that the time is binary and is 1/4 th of a microsecond in Cooja.
  //uint32_t microsecond_packet_interval = 47221;//46000 causes printouts to not happen for mote 1, but packets are sent. That's insane. // 7 ms is the lowest that yields results
    
  uint32_t microseconds_start = 24000;
  uint32_t microseconds_stop = 5000;
  uint32_t microsecond_interval = 250;
  uint32_t microseconds_between_intervals = 60000;
  uint32_t packets_per_interval = 256;
  uint32_t packet_size = 88;
  uint32_t packet_size_interval = 8;
  uint32_t min_packet_size = 0;
  uint32_t cur_index = 0;
  bool continue_application = 1;
  // Used for real mote. Since it takes a few hundred µs to calculate waiting time, we underestimate.
  // 11050 results in packet sent every 11.5 ms
  uint32_t microsecond_packet_interval = 49999;

  uint32_t last_time_sent = 0;

  char *alphabet = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"
                   "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"
                   "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz";

  void sendPacket() {
    call Leds.led0Toggle();

    stats.seqno++;
    stats.sender = TOS_NODE_ID;
    stats.interval = REPORT_PERIOD;

    call IPStats.get(&stats.ip);
    call UDPStats.get(&stats.udp);
    call Status.sendto(&route_dest, alphabet, (call Random.rand16() % 12)*8); // SPI 54 calls between 9-10 for rxdone and packet size 36. 15 calls for packet size 116. 2 bytes are read for each rxDone.
    //printf("Sent packet\n");
  }

  int iteration = 0;
  task void sendPeriodicPacket() {
  	//printf("nr_sending: %d\n", nr_sending);
    //uint32_t cur_time;
    //uint32_t wait_time = 0;
    //uint32_t ms_to_wait, microseconds_to_wait;
    // Start sending packet if the previous one has been sent. The mote won't actually start sending one until do_send is set to 1. But, we will return from attemptSend
    // if do_send is 0, which means we get to actually send the packet the moment it is time for it.
    /*if (udpechopsent) {
    	udpechopsent = 0;
    	do_send = 0;
    	sendPacket();
    } else {
    	post sendPeriodicPacket();
    	return;
    }*/
    //if (!continue_application)
  	//	return;
    //cur_time = call AccurateTimer.get();
    /*if (!udpechopsent) {
      post sendPeriodicPacket();
      return;
    }*/
    
    /*if (nr_sending >= 3) {
      post sendPeriodicPacket();
      return;
    }*/
    ++nr_sending;
    udpechopsent = 1;
    
    #if ALL_CONTEXTS_APP
    if (curseqno % 255 == 0 && ++iteration == 3) {  // Send 127*3 packets for each round
    	iteration = 0;
    	curseqno = 0;
   		microsecond_packet_interval -= microsecond_interval;
   		if (microsecond_packet_interval < microseconds_stop) {
   			microsecond_packet_interval = microseconds_start;
   			if (packet_size == 88)
   				packet_size = 44;
   			else if (packet_size == 44)
   				packet_size = 0;
   			else
   				packet_size -= packet_size_interval;
   			if (packet_size < min_packet_size) {
   				// End of application
   				continue_application = 0;
   			}
   			// It is neater if we can distinguish between different packet size traces first, and afterwards split up into different pps files
   			call StatusTimer.startOneShot(40000);
   		} else {
   			call StatusTimer.startOneShot(15000);
   		}
   		return;
   	}
   	#endif

    //udpechopsent = 0;
    //wait_time = (microsecond_packet_interval - ((cur_time-last_time_sent) % microsecond_packet_interval));
    //ms_to_wait = wait_time / 1000;
    //microseconds_to_wait = wait_time % 1000;
    //call BusyWait.wait(wait_time);
    //call BusyWait.wait(microseconds_to_wait);
    //call StatusTimer.startOneShot(ms_to_wait);
    //last_time_sent = call AccurateTimer.get();
    
    sendPacket();
    
    call StatusTimer.startOneShot(25);
    //post sendPeriodicPacket();
  }

  #define USE_MS_TIMER 0

  event void StatusTimer.fired() {
  	if (!continue_application)
  		return;
  	
  	if (USE_MS_TIMER) {
  		if (!timerStarted) {
  			call StatusTimer.startPeriodic(microsecond_packet_interval/1000);  // StatusTimer is a millisecond clock.
      		timerStarted = 1;
      		sendPacket();
  		} else {
  			call QuickSend.DoQuickSend();
  		}
  		return;
  	}

	do_send = 1;
    last_time_sent = call AccurateTimer.get();
    post sendPeriodicPacket();
  }
}
