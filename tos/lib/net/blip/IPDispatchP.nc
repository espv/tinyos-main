/*
 * "Copyright (c) 2008 The Regents of the University  of California.
 * All rights reserved."
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose, without fee, and without written agreement is
 * hereby granted, provided that the above copyright notice, the following
 * two paragraphs and the author appear in all copies of this software.
 *
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT
 * OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF
 * CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS."
 *
 */

#include <lib6lowpan/blip-tinyos-includes.h>
#include <lib6lowpan/6lowpan.h>
#include <lib6lowpan/lib6lowpan.h>
#include <lib6lowpan/ip.h>
#include <lib6lowpan/in_cksum.h>
#include <lib6lowpan/ip_malloc.h>

#include "blip_printf.h"
#include "IPDispatch.h"
#include "BlipStatistics.h"
#include "table.h"

/*
 * Provides IP layer reception to applications on motes.
 *
 * @author Stephen Dawson-Haggerty <stevedh@cs.berkeley.edu>
 */

module IPDispatchP {
  provides {
    interface SplitControl;
    interface Init @exactlyonce();

    // interface for protocols not requiring special hand-holding
    interface IPLower;

    interface BlipStatistics<ip_statistics_t>;
  }
  uses {
    /* link-layer wiring */
    interface SplitControl as RadioControl;

    interface Packet as BarePacket;
    interface Send as Ieee154Send;
    interface Receive as Ieee154Receive;

    /* context lookup */
    interface NeighborDiscovery;

    interface ReadLqi;
    interface PacketLink;
    interface LowPowerListening;

    /* buffers for outgoing fragments */
    interface Pool<message_t> as FragPool;
    interface Pool<struct send_info> as SendInfoPool;
    interface Pool<struct send_entry> as SendEntryPool;
    interface Queue<struct send_entry *> as SendQueue;

    /* expire reconstruction */
    interface Timer<TMilli> as ExpireTimer;

    interface Leds;

    interface EventFramework;
  }
} implementation {

#define HAVE_LOWPAN_EXTERN_MATCH_CONTEXT
int lowpan_extern_read_context(struct in6_addr *addr, int context) {
  return call NeighborDiscovery.getContext(context, addr);
}

int lowpan_extern_match_context(struct in6_addr *addr, uint8_t *ctx_id) {
  return call NeighborDiscovery.matchContext(addr, ctx_id);
}

  // generally including source files like this is a no-no.  I'm doing
  // this in the hope that the optimizer will do a better job when
  // they're part of a component.
#include <lib6lowpan/ieee154_header.c>
#include <lib6lowpan/lib6lowpan.c>
#include <lib6lowpan/lib6lowpan_4944.c>
#include <lib6lowpan/lib6lowpan_frag.c>

  enum {
    S_RUNNING,
    S_STOPPED,
    S_STOPPING,
  };
  uint8_t state = S_STOPPED;
  bool radioBusy;
  bool ack_required=TRUE;
  uint8_t current_local_label = 0;
  ip_statistics_t stats;

  uint8_t iplower_send_addr;
  uint8_t state_not_running;
  uint8_t s_info_is_null;
  uint8_t enqueue_not_success;
  uint8_t sendTask_addr;
  uint8_t ieee154receive_receive_addr;
  uint8_t ret_under_0;
  uint8_t headers_lowmsg_nalp;
  uint8_t hasFrag1_and_n_header;
  uint8_t recon_size_cond;
  uint8_t busy_or_not_running;
  uint8_t send_queue_empty;
  uint8_t failed_to_send;
  uint8_t ieee154send_senddone_addr;
  uint8_t radiocontrol_startdone_addr;
  uint8_t splitcontrol_stop_addr;

  // this in theory could be arbitrarily large; however, it needs to
  // be large enough to hold all active reconstructions, and any tags
  // which we are dropping.  It's important to keep dropped tags
  // around for a while, or else there are pathological situations
  // where you continually allocate buffers for packets which will
  // never complete.

  ////////////////////////////////////////
  //
  //

  table_t recon_cache;

  // table of packets we are currently receiving fragments from, that
  // are destined to us
  struct lowpan_reconstruct recon_data[N_RECONSTRUCTIONS];

  //
  //
  ////////////////////////////////////////

  void reconstruct_clear(void *ent) {
    struct lowpan_reconstruct *recon = (struct lowpan_reconstruct *)ent;
    memclr((uint8_t *)&recon->r_meta, sizeof(struct ip6_metadata));
    recon->r_timeout = T_UNUSED;
    recon->r_buf = NULL;
  }

  bool send_info_null;
  struct send_info *getSendInfo() {
    struct send_info *ret = call SendInfoPool.get();
    // Queue dequeuing
    send_info_null = ret == NULL;
    // If ret is NULL, this means that the packet gets dropped.
    // Next task should be to find out exactly when this happens.
    if (ret == NULL) {
      // QUEUECOND send_info_queue empty and SRVEXIT
      call EventFramework.trace_event(134);
      return ret;
    }

    // QUEUECOND send_info_queue notempty
    ret->_refcount = 1;
    ret->upper_data = NULL;
    ret->failed = FALSE;
    ret->link_transmissions = 0;
    ret->link_fragments = 0;
    ret->link_fragment_attempts = 0;
    return ret;
  }
#define SENDINFO_INCR(X) ((X)->_refcount)++
void SENDINFO_DECR(struct send_info *si) {
  if (--(si->_refcount) == 0) {
    //if (TOS_NODE_ID == 2)
    //  printf("call SendInfoPool.put, size: %d\n", call SendInfoPool.size());
    // Queue enqueuing
    call SendInfoPool.put(si);
  }
}

  command error_t SplitControl.start() {
    return call RadioControl.start();
  }

  command error_t SplitControl.stop() {
    if (!radioBusy) {
      state = S_STOPPED;
      return call RadioControl.stop();
    } else {
      // if there's a packet in the radio, wait for it to exit before
      // stopping
      state = S_STOPPING;
      return SUCCESS;
    }
  }

  event void RadioControl.startDone(error_t error) {
#ifdef LPL_SLEEP_INTERVAL
    call LowPowerListening.setLocalWakeupInterval(LPL_SLEEP_INTERVAL);
#endif

    if (error == SUCCESS) {
      call Leds.led2Toggle();
      call ExpireTimer.startPeriodic(FRAG_EXPIRE_TIME);
      state = S_RUNNING;
      radioBusy = FALSE;
    }

    signal SplitControl.startDone(error);
  }

  event void RadioControl.stopDone(error_t error) {
    signal SplitControl.stopDone(error);
  }

  command error_t Init.init() {
    // ip_malloc_init needs to be in init, not booted, because
    // context for coap is initialised in init
    ip_malloc_init();

    call BlipStatistics.clear();

    /* set up our reconstruction cache */
    table_init(&recon_cache, recon_data, sizeof(struct lowpan_reconstruct), N_RECONSTRUCTIONS);
    table_map(&recon_cache, reconstruct_clear);

    return SUCCESS;
  }

  /*
   *  Receive-side code.
   */
  void deliver(struct lowpan_reconstruct *recon) {
    struct ip6_hdr *iph = (struct ip6_hdr *)recon->r_buf;
    // This function takes a consistent 59 clock ticks!
    // printf("deliver [%i]: ", recon->r_bytes_rcvd);
    // printf_buf(recon->r_buf, recon->r_bytes_rcvd);

    //printf("IPDispatchP: Received IPv6 Packet\n");
    //printf(  "  source:    ");
    //printf_in6addr(&iph->ip6_src);
    //printf("\n  dest:      ");
    //printf_in6addr(&iph->ip6_dst);
    //printf("\n  hop limit: %i\n", iph->ip6_hlim);

    /* the payload length field is always compressed, have to put it back here */
    iph->ip6_plen = htons(recon->r_bytes_rcvd - sizeof(struct ip6_hdr));
    signal IPLower.recv(iph, (void *)(iph + 1), &recon->r_meta);

    ip_free(recon->r_buf);
    recon->r_timeout = T_UNUSED;
    recon->r_buf = NULL;

  }

  /*
   * Bulletproof recovery logic is very important to make sure we
   * don't get wedged with no free buffers.
   *
   * The table is managed as follows:
   *  - unused entries are marked T_UNUSED
   *  - entries which
   *     o have a buffer allocated
   *     o have had a fragment reception before we fired
   *     are marked T_ACTIVE
   *  - entries which have not had a fragment reception during the last timer period
   *     and were active are marked T_ZOMBIE
   *  - zombie receptions are deleted: their buffer is freed and table entry marked unused.
   *  - when a fragment is dropped, it is entered into the table as T_FAILED1.
   *     no buffer is allocated
   *  - when the timer fires, T_FAILED1 entries are aged to T_FAILED2.
   * - T_FAILED2 entries are deleted.  Incomming fragments with tags
   *     that are marked either FAILED1 or FAILED2 are dropped; this
   *     prevents us from allocating a buffer for a packet which we
   *     have already dropped fragments from.
   *
   */
  void reconstruct_age(void *elt) {
    struct lowpan_reconstruct *recon = (struct lowpan_reconstruct *)elt;
    /*if (recon->r_timeout != T_UNUSED)
      printf("recon src: 0x%x tag: 0x%x buf: %p recvd: %i/%i\n",
                 recon->r_source_key, recon->r_tag, recon->r_buf,
                 recon->r_bytes_rcvd, recon->r_size);*/
    switch (recon->r_timeout) {
    case T_ACTIVE:
      recon->r_timeout = T_ZOMBIE; break; // age existing receptions
    case T_FAILED1:
      recon->r_timeout = T_FAILED2; break; // age existing receptions
    case T_ZOMBIE:
    case T_FAILED2:
      // deallocate the space for reconstruction
      //printf("timing out buffer: src: %i tag: %i\n", recon->r_source_key, recon->r_tag);
      if (recon->r_buf != NULL) {
        //printf("ip_free(%p)\n", recon->r_buf);
        ip_free(recon->r_buf);
      }
      recon->r_timeout = T_UNUSED;
      recon->r_buf = NULL;
      break;
    }
  }

  void ip_print_heap() {
#ifdef PRINTFUART_ENABLED
    bndrt_t *cur = (bndrt_t *)heap;
    while (((uint8_t *)cur)  - heap < IP_MALLOC_HEAP_SIZE) {
      /*printf ("heap region start: %p length: %u used: %u\n",
                  cur, (*cur & IP_MALLOC_LEN), (*cur & IP_MALLOC_INUSE) >> 15);*/
      cur = (bndrt_t *)(((uint8_t *)cur) + ((*cur) & IP_MALLOC_LEN));
    }
#endif
  }

  event void ExpireTimer.fired() {
    table_map(&recon_cache, reconstruct_age);

    //printf("Frag pool size: %i\n", call FragPool.size());
    //printf("SendInfo pool size: %i\n", call SendInfoPool.size());
    //printf("SendEntry pool size: %i\n", call SendEntryPool.size());
    //printf("Forward queue length: %i\n", call SendQueue.size());
    //ip_print_heap();
    //printfflush();
  }

  /*
   * Return a structure for recording information about incoming fragments.
   */

  struct lowpan_reconstruct *get_reconstruct(uint16_t key, uint16_t tag) {
    struct lowpan_reconstruct *ret = NULL;
    int i;

    for (i = 0; i < N_RECONSTRUCTIONS; i++) {
      struct lowpan_reconstruct *recon = (struct lowpan_reconstruct *)&recon_data[i];

      if (recon->r_tag == tag &&
          recon->r_source_key == key) {

        if (recon->r_timeout > T_UNUSED) {
          recon->r_timeout = T_ACTIVE;
          ret = recon;
          goto done;

        } else if (recon->r_timeout < T_UNUSED) {
          // if we have already tried and failed to get a buffer, we
          // need to drop remaining fragments.
          ret = NULL;
          goto done;
        }
      }
      if (recon->r_timeout == T_UNUSED)
        ret = recon;
    }
  done:
    return ret;
  }

  /* Event is triggered when a packet is received fromt the radio */
  event message_t *Ieee154Receive.receive(message_t *msg,
                                          void *msg_payload,
                                          uint8_t len) {
    /* Signaled by UniqueReceiveP. This function signals IPNeighborDiscoveryP.recv. */
    struct packed_lowmsg lowmsg;
    struct ieee154_frame_addr frame_address;
    uint8_t *buf = msg_payload;
    size_t buflen = len;
    int ret;

    BLIP_STATS_INCR(stats.rx_total);

    /* unpack the 802.15.4 address fields */
    ret = unpack_ieee154_hdr(&buf, &buflen, &frame_address);

    ret_under_0 = ret < 0;
    if (ret_under_0) {
      // If there isn't any more data this is a malformed 6LoWPAN packet
      call EventFramework.trace_event(75);
      goto fail;
    }

    /* unpack any 6lowpan headers */
    lowmsg.data = buf;
    lowmsg.len  = buflen;
    lowmsg.headers = getHeaderBitmap(&lowmsg);
    headers_lowmsg_nalp = lowmsg.headers == LOWMSG_NALP;
    if (headers_lowmsg_nalp) {
      call EventFramework.trace_event(76);
      goto fail;
    }

    hasFrag1_and_n_header = hasFrag1Header(&lowmsg) || hasFragNHeader(&lowmsg);
    if (hasFrag1_and_n_header) {  // Not happening
      // start reassembly
      int rv;
      struct lowpan_reconstruct *recon;
      uint16_t tag, source_key;

      source_key = ieee154_hashaddr(&frame_address.ieee_src);
      getFragDgramTag(&lowmsg, &tag);
      recon = get_reconstruct(source_key, tag);

      if (!recon) {
        call EventFramework.trace_event(77);
        goto fail;
      }

      /* fill in metadata: on fragmented packets, it applies to the
         first fragment only  */
      memcpy(&recon->r_meta.sender, &frame_address.ieee_src,
             sizeof(ieee154_addr_t));
      recon->r_meta.lqi = call ReadLqi.readLqi(msg);
      recon->r_meta.rssi = call ReadLqi.readRssi(msg);

      if (hasFrag1Header(&lowmsg)) {
        // Fail if the buffer is already allocated. In that case we have already
        // received the Frag1 header.
        if (recon->r_buf != NULL) {
          call EventFramework.trace_event(78);
          goto fail;
        }
        rv = lowpan_recon_start(&frame_address, recon, buf, buflen);
      } else {
        // Fail if we try to reconstruct a packet without receiving the Frag1
        // header first.
        if (recon->r_buf == NULL) {
          call EventFramework.trace_event(79);
          goto fail;
        }
        rv = lowpan_recon_add(recon, buf, buflen);
      }

      if (rv < 0) {
        recon->r_timeout = T_FAILED1;
        call EventFramework.trace_event(80);
        goto fail;
      } else {
        // printf("start recon buf: %p\n", recon->r_buf);
        recon->r_timeout = T_ACTIVE;
        recon->r_source_key = source_key;
        recon->r_tag = tag;
      }

      if (recon->r_size == recon->r_bytes_rcvd) {
        deliver(recon);
      }

    } else {  // Happening
      /* no fragmentation, just deliver it */
      int rv;
      struct lowpan_reconstruct recon;

      /* fill in metadata */
      memcpy(&recon.r_meta.sender, &frame_address.ieee_src,
             sizeof(ieee154_addr_t));
      recon.r_meta.lqi = call ReadLqi.readLqi(msg);
      recon.r_meta.rssi = call ReadLqi.readRssi(msg);

      buf = getLowpanPayload(&lowmsg);
      if ((rv = lowpan_recon_start(&frame_address, &recon, buf, buflen)) < 0) {
        goto fail;
      }

      recon_size_cond = recon.r_size == recon.r_bytes_rcvd;
      if (recon_size_cond) {
        deliver(&recon);
      } else {
        ip_free(recon.r_buf);
      }
    }
    goto done;
  fail:
    BLIP_STATS_INCR(stats.rx_drop);
  done:

    return msg;
  }


  /*
   * Send-side functionality
   */
  task void sendTask() {
    /* Posted within IPDispatchP.send */
    struct send_entry *s_entry;

    busy_or_not_running = radioBusy || state != S_RUNNING;

    if (busy_or_not_running) {
      call EventFramework.trace_event(70);
      return;
    }

    send_queue_empty = call SendQueue.empty();
    if (send_queue_empty) {
      return;
    }
    // this does not dequeue
    s_entry = call SendQueue.head();

#ifdef LPL_SLEEP_INTERVAL
    call LowPowerListening.setRemoteWakeupInterval(s_entry->msg,
            call LowPowerListening.getLocalWakeupInterval());
#endif

    if (s_entry->info->failed) {
      call EventFramework.trace_event(72);
      dbg("Drops", "drops: sendTask: dropping failed fragment\n");
      goto fail;
    }

    failed_to_send = (call Ieee154Send.send(s_entry->msg, call BarePacket.payloadLength(s_entry->msg))) != SUCCESS;
    if (failed_to_send) {
      call EventFramework.trace_event(73);
      dbg("Drops", "drops: sendTask: send failed\n");
      goto fail;
    } else {
    
      radioBusy = TRUE;
    }

    //printf("End of sendTask\n");
    return;
  fail:
    call EventFramework.trace_event(41);
    post sendTask();
    BLIP_STATS_INCR(stats.tx_drop);

    // deallocate the memory associated with this request.
    // other fragments associated with this packet will get dropped.
    s_entry->info->failed = TRUE;
    SENDINFO_DECR(s_entry->info);
    call FragPool.put(s_entry->msg);
    call SendEntryPool.put(s_entry);
    call SendQueue.dequeue();

  }

  /*
   *  it will pack the message into the fragment pool and enqueue
   *  those fragments for sending
   *
   * it will set
   *  - payload length
   *  - version, traffic class and flow label
   *
   * the source and destination IP addresses must be set by higher
   * layers.
   */
  command error_t IPLower.send(struct ieee154_frame_addr *frame_addr,
                               struct ip6_packet *msg,
                               void  *data) {
    /* Called within IPNeighborDiscoveryP.send */  
    struct lowpan_ctx ctx;
    struct send_info  *s_info;
    struct send_entry *s_entry;
    message_t *outgoing;

    int frag_len = 1;
    error_t rc = SUCCESS;
      
    // This function takes exactly 44 clock ticks! Is called within UniqueReceiveP.SubReceive.receive
    state_not_running = state != S_RUNNING;
    if (state != S_RUNNING) {
      call EventFramework.trace_event(74);
      return EOFF;
    }


    //check whether the destination address is a multicast address or not
    if(frame_addr->ieee_dst.i_saddr==IEEE154_BROADCAST_ADDR)
      ack_required=FALSE;
    else
      ack_required=TRUE;

    /* set version to 6 in case upper layers forgot */
    msg->ip6_hdr.ip6_vfc &= ~IPV6_VERSION_MASK;
    msg->ip6_hdr.ip6_vfc |= IPV6_VERSION;

    ctx.tag = current_local_label++;
    ctx.offset = 0;

    s_info = getSendInfo();

    if (s_info == NULL) {
      // This results in a packet dropped and not forwarded.
      call EventFramework.trace_event(240);
      rc = ERETRY;
      goto cleanup_outer;
    }
    s_info->upper_data = data;

    while (frag_len > 0) {
      
      s_entry  = call SendEntryPool.get();
      outgoing = call FragPool.get();
      
      if (s_entry == NULL || outgoing == NULL) {
        if (s_entry != NULL) {
          call SendEntryPool.put(s_entry);
        }
        if (outgoing != NULL) {
          call FragPool.put(outgoing);
        }
        // this will cause any fragments we have already enqueued to
        // be dropped by the send task.
        s_info->failed = TRUE;
        rc = ERETRY;
        goto done;
      }

      call BarePacket.clear(outgoing);
      frag_len = lowpan_frag_get(call Ieee154Send.getPayload(outgoing, 0),
                                 call BarePacket.maxPayloadLength(),
                                 msg,
                                 frame_addr,
                                 &ctx);
      if (frag_len < 0) {
        //printf(" get frag error: %i\n", frag_len);
      }

      //printf("fragment length: %i offset: %i\n", frag_len, ctx.offset);
      call BarePacket.setPayloadLength(outgoing, frag_len);

      if (frag_len <= 0) {
        call FragPool.put(outgoing);
        call SendEntryPool.put(s_entry);
        goto done;
      }

      call EventFramework.trace_event(145);
      /*if (the_main_packet && TOS_NODE_ID == 2) {
      	the_main_packet = 0;
      	call SendQueue.enqueue(s_entry);
      	call SendQueue.enqueue(s_entry);
      }*/
      enqueue_not_success = call SendQueue.enqueue(s_entry) != SUCCESS;
      if (enqueue_not_success) {
        BLIP_STATS_INCR(stats.encfail);
        s_info->failed = TRUE;
        // Because we were unable to add this fragment to the send queue we need
        // to return the fragment and send entry to their respective pools.
        // The s_info will be taken care of in done:
        call FragPool.put(outgoing);
        call SendEntryPool.put(s_entry);
        //printf("drops: IP send: enqueue failed\n");
        goto done;
      }

      s_info->link_fragments++;
      s_entry->msg = outgoing;
      s_entry->info = s_info;

      /* configure the L2 */
      if (frame_addr->ieee_dst.ieee_mode == IEEE154_ADDR_SHORT &&
          frame_addr->ieee_dst.i_saddr == IEEE154_BROADCAST_ADDR) {
        call PacketLink.setRetries(s_entry->msg, 0);
      } else {
        call PacketLink.setRetries(s_entry->msg, BLIP_L2_RETRIES);
      }
      call PacketLink.setRetryDelay(s_entry->msg, BLIP_L2_DELAY);

      SENDINFO_INCR(s_info);
    }

    // printf("got %i frags\n", s_info->link_fragments);
  done:
    BLIP_STATS_INCR(stats.sent);
    SENDINFO_DECR(s_info);
    // Task enqueuing
    call EventFramework.trace_event(41);
    post sendTask();
  cleanup_outer:
    return rc;
  }

  event void Ieee154Send.sendDone(message_t *msg, error_t error) {
    struct send_entry *s_entry = call SendQueue.head();
    call EventFramework.trace_event(166);
    if (TOS_NODE_ID == 1) {
      udpechopsent = 1;  // Used by mote 1
      nr_sending--;
      //curseqno = (call CC2420PacketBody.getHeader(m_msg))->dsn;
  	}

    radioBusy = FALSE;

    if (state == S_STOPPING) {
      call RadioControl.stop();
      state = S_STOPPED;
      goto done;
    }

    s_entry->info->link_transmissions += (call PacketLink.getRetries(msg));
    s_entry->info->link_fragment_attempts++;

 //acknowledgements are not required for multicast packets, useful for fragmentation
   if (!call PacketLink.wasDelivered(msg) && ack_required) {
      // Removed printout because we don't want printouts when tracing.
      /*printf("sendDone: was not delivered! (%i tries)\n",
                 call PacketLink.getRetries(msg));*/
      s_entry->info->failed = TRUE;
      signal IPLower.sendDone(s_entry->info);
/*       if (s_entry->info->policy.dest[0] != 0xffff) */
/*         dbg("Drops", "drops: sendDone: frag was not delivered\n"); */
      // need to check for broadcast frames
      // BLIP_STATS_INCR(stats.tx_drop);
    } else if (s_entry->info->link_fragment_attempts ==
               s_entry->info->link_fragments) {
      signal IPLower.sendDone(s_entry->info);
    }

  done:
    // kill off any pending fragments
    SENDINFO_DECR(s_entry->info);
    call FragPool.put(s_entry->msg);
    call SendEntryPool.put(s_entry);
    call SendQueue.dequeue();

    post sendTask();  // Why is this being posted here? Is it to send any potential packets that are waiting to be sent?
    // Task enqueuing
    call EventFramework.trace_event(41);
    printf("e\n");
  }

  /*
   * BlipStatistics interface
   */
  command void BlipStatistics.get(ip_statistics_t *statistics) {
#ifdef BLIP_STATS_IP_MEM
    stats.fragpool = call FragPool.size();
    stats.sendinfo = call SendInfoPool.size();
    stats.sendentry= call SendEntryPool.size();
    stats.sndqueue = call SendQueue.size();
    stats.heapfree = ip_malloc_freespace();
    /*printf("frag: %i sendinfo: %i sendentry: %i sendqueue: %i heap: %i\n",
               stats.fragpool,
               stats.sendinfo,
               stats.sendentry,
               stats.sndqueue,
               stats.heapfree);*/
#endif
    memcpy(statistics, &stats, sizeof(ip_statistics_t));

  }

  command void BlipStatistics.clear() {
    memclr((uint8_t *)&stats, sizeof(ip_statistics_t));
  }

}
