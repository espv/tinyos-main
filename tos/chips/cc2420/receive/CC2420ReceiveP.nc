/*
 * Copyright (c) 2005-2006 Arch Rock Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the
 *   distribution.
 * - Neither the name of the Arch Rock Corporation nor the names of
 *   its contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * ARCHED ROCK OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE
 */

/**
 * @author Jonathan Hui <jhui@archrock.com>
 * @author David Moss
 * @author Jung Il Choi
 * @author JeongGil Ko
 * @author Razvan Musaloiu-E
 * @version $Revision: 1.21 $ $Date: 2009/09/17 23:36:36 $
 */

#include "IEEE802154.h"
#include "message.h"
#include "AM.h"

module CC2420ReceiveP @safe() {

  provides interface Init;
  provides interface StdControl;
  provides interface CC2420Receive;
  provides interface Receive;
  provides interface ReceiveIndicator as PacketIndicator;

  uses interface GeneralIO as CSN;
  uses interface GeneralIO as FIFO;
  uses interface GeneralIO as FIFOP;
  uses interface GpioInterrupt as InterruptFIFOP;

  uses interface Resource as SpiResource;
  uses interface CC2420Fifo as RXFIFO;
  uses interface CC2420Strobe as SACK;
  uses interface CC2420Strobe as SFLUSHRX;
  uses interface CC2420Packet;
  uses interface CC2420PacketBody;
  uses interface CC2420Config;
  uses interface PacketTimeStamp<T32khz,uint32_t>;
  //uses interface PacketTimeStamp<TMicro,uint32_t>;

  uses interface CC2420Strobe as SRXDEC;
  uses interface CC2420Register as SECCTRL0;
  uses interface CC2420Register as SECCTRL1;
  uses interface CC2420Ram as KEY0;
  uses interface CC2420Ram as KEY1;
  uses interface CC2420Ram as RXNONCE;
  uses interface CC2420Ram as RXFIFO_RAM;
  uses interface CC2420Strobe as SNOP;

  uses interface Leds;

  uses interface EventFramework;
}

implementation {

  typedef enum {
    S_STOPPED,
    S_STARTED,
    S_RX_LENGTH,
    S_RX_DEC,
    S_RX_DEC_WAIT,
    S_RX_FCF,
    S_RX_PAYLOAD,
  } cc2420_receive_state_t;

  enum {
    RXFIFO_SIZE = 128,
    TIMESTAMP_QUEUE_SIZE = 8,
    SACK_HEADER_LENGTH = 7,
  };

  uint32_t m_timestamp_queue[ TIMESTAMP_QUEUE_SIZE ];

  uint8_t m_timestamp_head;
  
  uint8_t m_timestamp_size;
  
  /** Number of packets we missed because we were doing something else */
#ifdef CC2420_HW_SECURITY
  norace uint8_t m_missed_packets;
#else
  uint8_t m_missed_packets;
#endif

  /** TRUE if we are receiving a valid packet into the stack */
  bool receivingPacket;
  
  /** The length of the frame we're currently receiving */
  norace uint8_t rxFrameLength;
  
  norace uint8_t m_bytes_left;
  
  norace message_t* ONE_NOK m_p_rx_buf;

  message_t m_rx_buf;
#ifdef CC2420_HW_SECURITY
  norace cc2420_receive_state_t m_state;
  norace uint8_t packetLength = 0;
  norace uint8_t pos = 0;
  norace uint8_t secHdrPos = 0;
  uint8_t nonceValue[16] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  norace uint8_t skip;
  norace uint8_t securityOn = 0;
  norace uint8_t authentication = 0;
  norace uint8_t micLength = 0;
  uint8_t flush_flag = 0;
  uint16_t startTime = 0;

  void beginDec();
  void dec();
#else
  cc2420_receive_state_t m_state;
#endif

  uint8_t interruptfifop_fired_addr;
  uint8_t rxfifo_readDone_addr;
  uint8_t fifo_get_addr;
  uint8_t fifop_get_addr;
  uint8_t mac_packet_size_addr;
  uint8_t flush_rxfifo_addr;
  uint8_t rxfifo_overflow_addr;
  uint8_t good_fcf_addr;
  uint8_t packet_too_large_addr;
  uint8_t start_next_packet_addr;
  uint8_t packet_buffered_addr;
  uint8_t ack_received_addr;
  uint8_t beginReceive_addr;
  uint8_t waitForNextPacket_addr;
  uint8_t stdcontrol_start_addr;
  uint8_t reset_state_addr;

  /***************** Prototypes ****************/
  void reset_state();
  void beginReceive();
  void receive();
  void waitForNextPacket();
  void flush();
  bool passesAddressCheck(message_t * ONE msg);

  task void receiveDone_task();

  /***************** Init Commands ****************/
  command error_t Init.init() {
    m_p_rx_buf = &m_rx_buf;
    return SUCCESS;
  }

  /***************** StdControl ****************/
  command error_t StdControl.start() {
    atomic {
      reset_state();
      m_state = S_STARTED;
      atomic receivingPacket = FALSE;
      /* Note:
         We use the falling edge because the FIFOP polarity is reversed. 
         This is done in CC2420Power.startOscillator from CC2420ControlP.nc.
       */
      call InterruptFIFOP.enableFallingEdge();
    }
    return SUCCESS;
  }
  
  command error_t StdControl.stop() {
    atomic {
      m_state = S_STOPPED;
      reset_state();
      call CSN.set();
      call InterruptFIFOP.disable();
    }
    return SUCCESS;
  }

  /***************** CC2420Receive Commands ****************/
  /**
   * Start frame delimiter signifies the beginning/end of a packet
   * See the CC2420 datasheet for details.
   */
  async command void CC2420Receive.sfd( uint32_t time ) {
    call EventFramework.trace_event(88);
    if ( m_timestamp_size < TIMESTAMP_QUEUE_SIZE ) {
      uint8_t tail =  ( ( m_timestamp_head + m_timestamp_size ) % 
                        TIMESTAMP_QUEUE_SIZE );
      m_timestamp_queue[ tail ] = time;
      call EventFramework.trace_event_custom_time(94, time*30);
      m_timestamp_size++;
    }
  }

  async command void CC2420Receive.sfd_dropped() {
    if ( m_timestamp_size ) {
      m_timestamp_size--;
    }
  }

  /***************** PacketIndicator Commands ****************/
  command bool PacketIndicator.isReceiving() {
    bool receiving;
    atomic {
      receiving = receivingPacket;
    }
    return receiving;
  }

  bool ack = 0;
  /***************** InterruptFIFOP Events ****************/
  async event void InterruptFIFOP.fired() {
    /* Entire packet trail takes in 32khz clock ticks 550, 358, 462, 314, 509.
     * Largest difference is 314 ~ 550. This means that goal should be to find these large
     * discrepancies. I have already found differences in 1-3 clock ticks in this function
     * and the attemptSend function, but that's almost nothing compared to the whole picture.
     *
     * One clue is that I've tested multiple larger functions, and found that none of them
     * have large differences in execution time when running them multiple times.
     * If we assume this to be the case for all functions, which I'm not ready to do,
     * the huge differences in runtime might be caused by scheduling of tasks. One way to find
     * out of this is to place traces in all the larger functions and see which order they're
     * called, which includes events. The events are called asynchronous, and might therefore
     * be called before or after important packet processing functions.
     * In fact, if this is the case, there might be potential for improving the task system.
     *
     * The clock tick difference between the last event in this function and IPDispatchP.receive
     * is exactly 71 ticks. What happens in those ticks, I don't know. But considering the amount
     * of time is completely consistent, it is not very interesting to know that at the moment.
     * Before the last trace in attemptSend, a new task is run. This has been monitored by placing
     * traces at the SchedulerBasicP taskloop. The task that runs this interrupt ends, a new one
     * is run and finished, and finally the attemptSend function is run in the last task.
     * Tasks run in the packet processing: 
     * 1: Runs this interrupt and IPDispatchP.receive, at least.
     * 2: Does something I don't know.
     * 3: Runs CC2420TransmitP.attemptSend, at least. NO, this is most likely wrong. The "loop start"
     *    event occurring lastly is sometimes called before and sometimes after attemptSend.
     *    Sometimes attemptSend is called after a "loop stop" event, without starting a new task.
     * 221, 238 cycles between task loop start, to reaching attemptSend. This is a significant
     * difference that might have something to do with MAC layer and waiting.
     * When testing, I found that the difference between two forwarding cases was 18 cycles.
     * The difference in the task loop start, to reaching attemptSend was 238 - 221 = 17.
     * This means that the greater differences seen might be solely because of this difference.
     * This is a very important discovery, and should be the main thing to study moving forward.
     * Additional examples to prove this hypothesis:
     * 1: Total time: 497. Last task loop cycles: 133. Subtract the two: 364 cycles.
     * 2: Total time: 602. Last task loop cycles: 238. Subtract the two: 364 cycles.
     * 3: Total time: 584. Last task loop cycles: 221. Subtract the two: 363 cycles.
     * 4: Total time: 381. Last task loop cycles: . Subtract the two: cycles.
     * New discovery: The last loop start event isn't always called, and in which case
     * there won't be any large delay! What happens when this event is called, and why
     * is it sometimes called before attemptSend and sometimes after?
     * It appears as though what is calling attemptSend is BackoffTimer.fired(). attemptSend
     * is not called long after the BackoffTimer is started, which means it is not causing
     * the large delay. Although, the BackoffTimer is started within the BackoffTimer.fired
     * function itself, which means it could still be causing the delay. It might be that
     * it is fired often.
     * Task: Find out when the BackoffTimer is started. What is most likely causing the delay
     * is that the timer is called at various times based on some variable which will be
     * the event we have to capture.
     * Solution for task: I finally found the entire reason. In CC2420CsmaP, there's an event
     * SubBackoff.requestInitialBackoff which creates a random number for backoff. If this random
     * number is replaced by a constant, the entire packet processing step becomes completely
     * deterministic +-1 clock ticks, which is not very much in the big picture.
     * The next step might actually be to report the findings to the supervisors and ask for
     * what the next step should be. Should there even be any instrumentation in this OS?
     *
     * Instrumentation doesn't seem to be needed when the device can handle each packet one by one.
     * However, when increasing the frequency of packets forwarded, this might be needed.
     * The reason why I initally thought this wouldn't be necessary is that the device seemed to
     * crash on high packet frequencies. The reason for this has been found, and it's in the
     * HplMsp430UartP.nc file. A busy waiting loop is causing the device to get hung up.
     * This was fixed by wrapping the function in an atomic block, which forces the entire
     * block to be executed without possibility of interruption in any way. Some state must
     * be set some way, and not set back, causing the issue. I should still investigate what
     * might cause the state to get corrupted, but isn't essential. What remains is to increase
     * the packet frequency with the fix and be able to see how long packets take to be forwarded
     * with extra delay.
     * One problem with testing now is that packets that have been sent and acked seem to be
     * sent again. Why, I don't know. It actually never happens if the packet doesn't get acked.
     * I want to know because the goal is to only send a packet with a certain payload and
     * sequence number once. This way, I can identify when specific packets are received and
     * sent.
     * Ways of figuring out issue:
     * 1: Find out if mote 1 sends the same packet multiple times. If so, problem solved.
     * 2: Find out if mote 2 receives the same packet multiple times or if the blip
     *    layer somehow keeps the same packet in the SendQueue even though it's sent.
     * Method 1 seems to not be what's happening because the sequence number is always
     * incremented in the UDPEchoP module. When mote 2 receives a packet, we should
     * check what the payload for the newly arrived packet is. Remember that there are
     * two tasks occurring: (1): reading packet and putting in blip queue, (2) reading
     * queue, de-queuing and sending packet. It could be that the queue gets filled up.
     * One immediate test could be to always empty buffer after reading it, and see if it
     * becomes correct.
     *
     * New understanding of how the data flow goes when receiving a packet:
     * 1: This event (hardware interrupt) is evoked.
     * 2: IPDispatchP.Ieee154Receive.receive event is evoked after reading the packet from the radio.
     *    This step reads the packet, sends it up to the blip layer and decides whether to forward it or not.
     * 3: IPDispatchP.sendTask task is posted from previous step (IPDispatchP.IPLower.send) sends the packet.
     *
     * New theory for why packets are "dropped": The two first steps are events. If new events are called,
     * it might eventually cause the task queue to have to drop events, in which case packets will be dropped.
     * Way to test it: Print out number of tasks are in the queue in the task loop. 
     *
     * Weird things that can happen that have been proven to happen in Cooja:
     * 1: This hardware interrupt event can be called when the function is already running.
     * 2: IPDispatchP.sendTask can return because radioBusy || state != S_RUNNING. This returns
     *    without doing anything or reposting the task. Why not re-post the task?
     * 3: UniqueSendP.
     *
     * For our forwarding app, mote 2 should have this event called twice for every packet to be forwarded
     * to mote 3, when acks are enabled. With hardware acks and software acks, this event is called. Why,
     * I don't know. With acks disabled, acks don't cause this event to be called. However, it doesn't really
     * work to disabled them. The motes keep resending the packets because they don't get acks.
     *
     * Ack from mote 3 is received nearly 200 ms after packet has been received from mote 1. The time it takes
     * is from processing the packet. When packet frequency is high, it appears that this event isn't called enough
     * times, from looking at the radio messages. One event call should happen for each packet received
     * from mote 1 and ack from mote 3. This does not happen even if radio comm is detected in radio messages.
     * This might be due to overflow in an event call queue in CC2420 low level drivers, or perhaps multiple packets
     * are expected to be processed in same event call. Next task should be to print out the packets received right
     * in this interrupt. Log whether packet is ack and its sequence number. With that information we can look
     * in the radio messages window and see if the packets match. A temporary solution is to trace events in the
     * function that is called when additional packets need to be read. This can reveal if this call reads multiple
     * packets even though no packets were missed in the previous call.
     *
     * THE ABOVE IS TRUE: This event isn't necessary called for each packet, but it appears that beginReceive is.
     * This means that by tracing beginReceive, we can capture all packets that are recorded in the Radio messages
     * window in Cooja it appears. By counting the number of packets received in Cooja, there were too few calls to
     * this event. However, by counting number of beginReceive calls, it added up. beginReceive is potentially called
     * multiple times when there are multiple packets awaiting. Initially I thought this was because of that only
     * happening when packets have previously been missed in this event, but that's not true. There can be multiple
     * packets awaiting at any time, but we can record all the necessary info by tracing the beginReceive function.
     *
     * The next steps to do:
     * - Since we now know that all packets that are logged in Radio messages window
     *   actually are received here in beginReceive(), we have to find out where
     *   they're lost. Problem is that packet with seq-no 4 is received, but isn't
     *   forwarded from mote 2 to mote 3. We know that mote 1 receives a packet with
     *   seq-no 4, but somewhere along the line it's not being processed anymore.
     * - Potential reasons for why packets aren't forwarded:
     *   - Too many events are scheduled, and the IPDispatchP.Ieee154Receive.receive event isn't called.
     *   - IPDispatchP.sendTask returns without sending the packet that is to be forwarded. (We know this happens).
     *     - One thing that can be done here is to read the sequence number of the packet to be sent in the sendTask
     *       before we return from the task. That might be problematic though, so a synchronization method might suffice.
     * Execution report: 
          5 packets forwarded and acked.
          But only 3 unique packets.
          This means that sendTask only completed 
          correctly 3 times.
          Only SRV task Stop3 actually sends a packet.
          After this happens, the MAC layer will make
          sure that the packet is acked by re-sending
          it if no ack has been confirmed within a
          certain amount of time.

          Same packet is forwarded and acked multiple
          times. But since the mote is so busy, it's
          unable to confirm the ack before it's time to
          re-send it. This does confirm something
          though, and that's that only 3/11 packets
          were enqueued on the sendQueue. We need
          to find out why the remaining 8 weren't.
          Next step should be to trace the
          IPDispatch.Ieee154Receive.receive event, 
          which sends the packet up the stack.
     *
     * 
     *
     * Example:
        6 packets received and acked from mote 1.
        6 calls to UniqueReceiveP.receive occur.
        Only 3 packets are forwarded, which means
        that somewhere between UniqueReceiveP.
        receive and enqueueing the packet in blip,
        a call is returning and ignoring a packet.
        *****************Done for now*************
     * Task: Why is UniqueReceiveP.receive called 5 times,
     *       while beginReceive is called 20 times?
     *       readDone is called ~2 times after beginReceive is called,
     *       and UniqueReceiveP is the next event signalled.
     *
     * - Cond2 in IPDispatchP.IPLower.send results in a packet dropped.
     * - CC2420ReceiveP.receiveDone_task is called as many times as packets
     *   that will be sent to the IP layer. This means that it is called
     *   less times than beginReceive is called. Find out why.
     *   - First off, receiveDone_task is only called for packets that
     *     are not acks.
     * - 6 packets are sent from mote 1 to 2. 5 are handled in receiveDone_task.
     *   The reason why only 5 are handled is that only 5 of the 6 packets are
     *   acked. seq-no 3 and 4 are sent right after each other, but only seq-no
     *   4 is acked by mote 2.
     *   This means that with the current packet flow, every event is tracked
     *   to capture the packets forwarded.
     *   5 packets are retrieved from mote 1 to mote 2 and acked. 4 packets
     *   are forwarded to mote 3 and acked. 1 packet is ignored and dropped in
     *   Cond2 in IPDispatchP.IPLower.send.
     * - Increase number of packets to send to see if more discrepancies occur.
     * 
     * Next things to track:
     * - What causes some packets to have to be re-sent and other treated immediately?
     *   Shouldn't the CC2420 chip capture all of the packets until the buffer is filled up?
     *   Could it be that the buffer does get filled up before dropping packets?
     *   Or could it be that 
     * - What causes the state to get to the place where Cond2 in IPDispatchP.IPLower.send
     *   happens?
     * - From what it looks like, the congestion occurs on the receiving end of mote 2. The
     *   transmitting task seems to always do its job.
     *
     * Runtime report:
     *  31 total packets sent from mote 1 to mote 2.
        7 total acks from mote 3 to mote 2.

        37 total readDone calls.

        One packet seems to not be treated in readDone.
        Could this be the packet that was never received?
        The question though is, why does mote 1
        re-send other packets, but this one time
        when mote 2 didn't receive a packet, it only
        sends once?
        It makes sense that that one packet was never
        received, because otherwise it would be treated
        in readDone. The reason why the other ones
        are re-sent is because it took too long time to
        handle them. One weird thing is that
        the TX/RX success rate is 100%, so mote 2 must
        have received the packet somehow, but it
        might be at a lower level. This should be the next
        task.
     *
     * It appears that readDone is only called for the packets
     * that are handled in UniqueReceiveP. 5 packets are handled
     * in UniqueReceiveP, and the pattern described in readDone
     * shows that 5 packets were handled, including 3 acks from mote 3.
     * It also shows that one ack was missing, which I don't understand.
     * Shouldn't a missed ack cause re-transmission of the packet?
     * This means we need to find out where the packets are dropped.
     *
     * I believe that beginReceive does what I believed readDone to do.
     * What's strange is that we don't appear to read duplicate packets,
     * even though that's supposed to be handled in UniqueReceive. Read
     * CC2420 data sheet and find out if that's dealt with there.
     *
     * Could it be that the duplicate packets aren't handled because
     * the mote is busy and the radio is "deleting" old packets as time
     * goes? It would be the only explanation I can think of to the fact
     * that no duplicate packets are read from the chip, yet many packets
     * read from the Radio messages window in Cooja are retransmissions
     * that are successfully sent.
     * Trace the radio chip somehow. See the movement with the packets
     * received.
     *
     * Next tasks: Trace retransmissions for both data packets and acks.
     *             We need to know when these happen.
     * Future task: Find out why most packets aren't received by the radio
     *              with high packet frequency. 
     *
     * Theory written originally in readDone event:
     * Somewhere else it says that FIFOP has a threshold of 127 bytes. This means I believe
     * that when the threshold has been reached, the buffer has to be read completely before
     * any more packets can be received. This means that m_bytes_left always starts at 127 bytes
     * and as more payload packets must be read, this if-statement is evaluated so that more of
     * the buffer is read. This if-statement is only evaluated when a payload was read just before.
     * Cond1 will happen when there are no more packets to read from the buffer.
     * After that, we will wait for new packets and for the FIFOP pin to go low, and then read
     * m_bytes_left = 127 bytes. If this buffer size was decreased to 64 for instance, we could
     * read packets as they are received.
     * This whole theory explains why we only receive one copy of packets. When we're busy, we can
     * only receive around two packets = 57*2 bytes in the buffer, which means we don't get all
     * the duplicate packets. We can however get many acks since they're just 5 bytes.
     * This theory isn't completely accurate, but an estimate that needs analysis of the CC2420
     * datasheet. Read about FIFO, FIFOP and RXFIFO. It seems that receiving last byte of a newly
     * arrived packets should activate FIFOP.
     *
     * When Cond1 in readDone happens, we know that the next packet to be read is the first 
     * one received after this. That means that the above paragraph is false. It's always
     * the newly received packets that are received and read. But, when everything has been
     * read from the RXFIFO, it gets flushed and reset. This means that the next packets that
     * arrive will be the next ones to be read. Anything that's received in between starting to
     * read RXFIFO and flushing RXFIFO doesn't get read.
     *
     * ( m_missed_packets && call FIFO.get() ) || !call FIFOP.get().
     * The above means that a packet is waiting. 
     * !call FIFO.get() && !call FIFOP.get()
     * The above means RXFIFO overflow, and need to read entire FIFO and flush it out.
     * That means that between the overflow and flushing, no new packets will be received.
     * 
     * By tracing FIFO.get() and FIFOP.get() in the readDone function, we can come to a conclusion
     * on whether new packets can be received and what kind of packet we're looking at (ack or data).
     */
    // HIRQENTRY
    //while (!(!call FIFO.get() && !call FIFOP.get()));
    //printf("RXFIFO overflow: %u\n", !call FIFO.get() && !call FIFOP.get());
    call EventFramework.trace_event(130);
    if ( m_state == S_STARTED ) {
#ifndef CC2420_HW_SECURITY
      m_state = S_RX_LENGTH;
      beginReceive();
#else
      m_state = S_RX_DEC;
      atomic receivingPacket = TRUE;
      beginDec();
#endif
    } else {
      m_missed_packets++;
    }

    // HIRQEXIT
    call EventFramework.trace_event(3);
  }

  /*****************Decryption Options*********************/
#ifdef CC2420_HW_SECURITY
  task void waitTask(){

    if(SECURITYLOCK == 1){
      post waitTask();
    }else{
      m_state = S_RX_DEC;
      beginDec();
    }
  }

  void beginDec(){
    if(call SpiResource.isOwner()) {
      dec();
    } else if (call SpiResource.immediateRequest() == SUCCESS) {
      dec();
    } else {
      call SpiResource.request();
    }
  }

  norace uint8_t decLoopCount = 0;

  task void waitDecTask(){

    cc2420_status_t status;

    call CSN.clr();
    status = call SNOP.strobe();
    call CSN.set();

    atomic decLoopCount ++;

    if(decLoopCount > 10){
      call CSN.clr();
      atomic call SECCTRL0.write((0 << CC2420_SECCTRL0_SEC_MODE) |
				 (0 << CC2420_SECCTRL0_SEC_M) |
				 (0 << CC2420_SECCTRL0_SEC_RXKEYSEL) |
				 (1 << CC2420_SECCTRL0_SEC_CBC_HEAD) |
				 (1 << CC2420_SECCTRL0_RXFIFO_PROTECTION)) ;
      call CSN.set();
      SECURITYLOCK = 0;
      call SpiResource.release();
      atomic flush_flag = 1;
      beginReceive();
    }else if(status & CC2420_STATUS_ENC_BUSY){
      post waitDecTask();
    }else{
      call CSN.clr();
      atomic call SECCTRL0.write((0 << CC2420_SECCTRL0_SEC_MODE) |
				 (0 << CC2420_SECCTRL0_SEC_M) |
				 (0 << CC2420_SECCTRL0_SEC_RXKEYSEL) |
				 (1 << CC2420_SECCTRL0_SEC_CBC_HEAD) |
				 (1 << CC2420_SECCTRL0_RXFIFO_PROTECTION)) ;
      call CSN.set();
      SECURITYLOCK = 0;
      call SpiResource.release();
      beginReceive();
    }

  }

  void waitDec(){
    cc2420_status_t status;
    call CSN.clr();
    status = call SNOP.strobe();
    call CSN.set();

    if(status & CC2420_STATUS_ENC_BUSY){
      atomic decLoopCount = 1;
      post waitDecTask();
    }else{
      call CSN.clr();
      atomic call SECCTRL0.write((0 << CC2420_SECCTRL0_SEC_MODE) |
				 (0 << CC2420_SECCTRL0_SEC_M) |
				 (0 << CC2420_SECCTRL0_SEC_RXKEYSEL) |
				 (1 << CC2420_SECCTRL0_SEC_CBC_HEAD) |
				 (1 << CC2420_SECCTRL0_RXFIFO_PROTECTION)) ;
      call CSN.set();
      SECURITYLOCK = 0;
      call SpiResource.release();
      beginReceive();
    }
  }

  void dec(){
    cc2420_header_t header;
    security_header_t secHdr;
    uint8_t mode, key, temp, crc;

    atomic pos = (packetLength+pos)%RXFIFO_SIZE;

#if ! defined(TFRAMES_ENABLED)
    atomic secHdrPos = (pos+11)%RXFIFO_SIZE;
#else
    atomic secHdrPos = (pos+10)%RXFIFO_SIZE;
#endif

    if (pos + 3 > RXFIFO_SIZE){
      temp = RXFIFO_SIZE - pos;
      call CSN.clr();
      atomic call RXFIFO_RAM.read(pos,(uint8_t*)&header, temp);
      call CSN.set();
      call CSN.clr();
      atomic call RXFIFO_RAM.read(0,(uint8_t*)&header+temp, 3-temp);
      call CSN.set();
    }else{
      call CSN.clr();
      atomic call RXFIFO_RAM.read(pos,(uint8_t*)&header, 3);
      call CSN.set();
    }

    packetLength = header.length+1;

    if(packetLength == 6){ // ACK packet
      m_state = S_RX_LENGTH;
      call SpiResource.release();
      beginReceive();
      return;
    }

    if (pos + sizeof(cc2420_header_t) > RXFIFO_SIZE){
      temp = RXFIFO_SIZE - pos;
      call CSN.clr();
      atomic call RXFIFO_RAM.read(pos,(uint8_t*)&header, temp);
      call CSN.set();
      call CSN.clr();
      atomic call RXFIFO_RAM.read(0,(uint8_t*)&header+temp, sizeof(cc2420_header_t)-temp);
      call CSN.set();
    }else{
      call CSN.clr();
      atomic call RXFIFO_RAM.read(pos,(uint8_t*)&header, sizeof(cc2420_header_t));
      call CSN.set();
    }

    if (pos+header.length+1 > RXFIFO_SIZE){
      temp = header.length - (RXFIFO_SIZE - pos);
      call CSN.clr();
      atomic call RXFIFO_RAM.read(temp,&crc, 1);
      call CSN.set();
    }else{
      call CSN.clr();
      atomic call RXFIFO_RAM.read(pos+header.length,&crc, 1);
      call CSN.set();
    }

    if(header.length+1 > RXFIFO_SIZE || !(crc << 7)){
      atomic flush_flag = 1;
      m_state = S_RX_LENGTH;
      call SpiResource.release();
      beginReceive();
      return;
    }
    if( (header.fcf & (1 << IEEE154_FCF_SECURITY_ENABLED)) && (crc << 7) ){
      if(call CC2420Config.isAddressRecognitionEnabled()){
	if(!(header.dest==call CC2420Config.getShortAddr() || header.dest==AM_BROADCAST_ADDR)){
	  packetLength = header.length + 1;
	  m_state = S_RX_LENGTH;
	  call SpiResource.release();
	  beginReceive();
	  return;
	}
      }
      if(SECURITYLOCK == 1){
	call SpiResource.release();
	post waitTask();
	return;
      }else{
	//We are going to decrypt so lock the registers
	atomic SECURITYLOCK = 1;

	if (secHdrPos + sizeof(security_header_t) > RXFIFO_SIZE){
	  temp = RXFIFO_SIZE - secHdrPos;
	  call CSN.clr();
	  atomic call RXFIFO_RAM.read(secHdrPos,(uint8_t*)&secHdr, temp);
	  call CSN.set();
	  call CSN.clr();
	  atomic call RXFIFO_RAM.read(0,(uint8_t*)&secHdr+temp, sizeof(security_header_t) - temp);
	  call CSN.set();
	} else {
	  call CSN.clr();
	  atomic call RXFIFO_RAM.read(secHdrPos,(uint8_t*)&secHdr, sizeof(security_header_t));
	  call CSN.set();
	}

	key = secHdr.keyID[0];

	if (secHdr.secLevel == NO_SEC){
	  mode = CC2420_NO_SEC;
	  micLength = 0;
	}else if (secHdr.secLevel == CBC_MAC_4){
	  mode = CC2420_CBC_MAC;
	  micLength = 4;
	}else if (secHdr.secLevel == CBC_MAC_8){
	  mode = CC2420_CBC_MAC;
	  micLength = 8;
	}else if (secHdr.secLevel == CBC_MAC_16){
	  mode = CC2420_CBC_MAC;
	  micLength = 16;
	}else if (secHdr.secLevel == CTR){
	  mode = CC2420_CTR;
	  micLength = 0;
	}else if (secHdr.secLevel == CCM_4){
	  mode = CC2420_CCM;
	  micLength = 4;
	}else if (secHdr.secLevel == CCM_8){
	  mode = CC2420_CCM;
	  micLength = 8;
	}else if (secHdr.secLevel == CCM_16){
	  mode = CC2420_CCM;
	  micLength = 16;
	}else{
	  atomic SECURITYLOCK = 0;
	  packetLength = header.length + 1;
	  m_state = S_RX_LENGTH;
	  call SpiResource.release();
	  beginReceive();
	  return;
	}

	if(mode < 4 && mode > 0) { // if mode is valid
  
	  securityOn = 1;

	  memcpy(&nonceValue[3], &(secHdr.frameCounter), 4);
	  skip = secHdr.reserved;

	  if(mode == CC2420_CBC_MAC || mode == CC2420_CCM){
	    authentication = 1;
	    call CSN.clr();
	    atomic call SECCTRL0.write((mode << CC2420_SECCTRL0_SEC_MODE) |
				       ((micLength-2)/2 << CC2420_SECCTRL0_SEC_M) |
				       (key << CC2420_SECCTRL0_SEC_RXKEYSEL) |
				       (1 << CC2420_SECCTRL0_SEC_CBC_HEAD) |
				       (1 << CC2420_SECCTRL0_RXFIFO_PROTECTION)) ;
	    call CSN.set();
	  }else{
	    call CSN.clr();
	    atomic call SECCTRL0.write((mode << CC2420_SECCTRL0_SEC_MODE) |
				       (1 << CC2420_SECCTRL0_SEC_M) |
				       (key << CC2420_SECCTRL0_SEC_RXKEYSEL) |
				       (1 << CC2420_SECCTRL0_SEC_CBC_HEAD) |
				       (1 << CC2420_SECCTRL0_RXFIFO_PROTECTION)) ;
	    call CSN.set();
	  }

	  call CSN.clr();
#ifndef TFRAMES_ENABLED
	  atomic call SECCTRL1.write(skip+11+sizeof(security_header_t)+((skip+11+sizeof(security_header_t))<<8));
#else
	  atomic call SECCTRL1.write(skip+10+sizeof(security_header_t)+((skip+10+sizeof(security_header_t))<<8));
#endif
	  call CSN.set();

	  call CSN.clr();
	  atomic call RXNONCE.write(0, nonceValue, 16);
	  call CSN.set();

	  call CSN.clr();
	  atomic call SRXDEC.strobe();
	  call CSN.set();

	  atomic decLoopCount = 0;
	  post waitDecTask();
	  return;

	}else{
	  atomic SECURITYLOCK = 0;
	  packetLength = header.length + 1;
	  m_state = S_RX_LENGTH;
	  call SpiResource.release();
	  beginReceive();
	  return;
	}
      }
    }else{
      packetLength = header.length + 1;
      m_state = S_RX_LENGTH;
      call SpiResource.release();
      beginReceive();
      return;
    }
  }
#endif
  /***************** SpiResource Events ****************/
  event void SpiResource.granted() {
#ifdef CC2420_HW_SECURITY
    if(m_state == S_RX_DEC){
      dec();
    }else{
      receive();
    }
#else
    receive();
#endif
  }
  
  /***************** RXFIFO Events ****************/
  /**
   * We received some bytes from the SPI bus.  Process them in the context
   * of the state we're in.  Remember the length byte is not part of the length
   */
  async event void RXFIFO.readDone( uint8_t* rx_buf, uint8_t rx_len,
                                    error_t error ) {
    /*
    * readDone call log:
    *   m_state is switched on.
    *   mote 1 to mote 2:
    *     - S_RX_LENGTH: Cond2, Stop3
    *     - S_RX_LENGTH: Cond6, Stop3
    *     - S_RX_FCF: Cond7, Cond9, Stop2-ack
    *   mote 3 to mote 2 (ack):
    *     - S_RX_LENGTH: Cond3, Stop3
    *     - S_RX_FCF: Cond7, Cond8, Stop3
    */
    cc2420_header_t* header;
    uint8_t tmpLen __DEPUTY_UNUSED__ = sizeof(message_t) - (offsetof(message_t, data) - sizeof(cc2420_header_t));
    uint8_t* COUNT(tmpLen) buf;
    
    uint8_t no_missed_packets;
    uint8_t old_m_state = m_state;
    //printf("RXFIFO overflow: %u\n", !call FIFO.get() && !call FIFOP.get());
    header = call CC2420PacketBody.getHeader( m_p_rx_buf );
    buf = TCAST(uint8_t* COUNT(tmpLen), header);
    no_missed_packets = (uint8_t)!m_missed_packets;
    rxFrameLength = buf[ 0 ];

    if (m_state == S_RX_LENGTH) {
      call EventFramework.trace_event(4);
      call EventFramework.trace_special_event(rxFrameLength);
    }
    else if (m_state == S_RX_FCF) {
      call EventFramework.trace_event(7);
    } else if (m_state == S_RX_PAYLOAD) {
      call EventFramework.trace_event(10);
    }
    switch( m_state ) {

    case S_RX_LENGTH:
      m_state = S_RX_FCF;
#ifdef CC2420_HW_SECURITY
      packetLength = rxFrameLength+1;
#endif
      if ( rxFrameLength + 1 > m_bytes_left
#ifdef CC2420_HW_SECURITY
           || flush_flag == 1
#endif
           ) {
        // When this happens, we know that the next packet to be read is the first one received after this.
        // Length of this packet is bigger than the RXFIFO, flush it out.
        call EventFramework.trace_event(42);
        //printf("Flush\n");
        flush();
        
      } else {
        if ( !call FIFO.get() && !call FIFOP.get() ) {
          /* Theory: Somewhere else it says that FIFOP has a threshold of 127 bytes. This means I believe
           * that when the threshold has been reached, the buffer has to be read completely before
           * any more packets can be received. This means that m_bytes_left always starts at 127 bytes
           * and as more payload packets must be read, this if-statement is evaluated so that more of
           * the buffer is read. This if-statement is only evaluated when a payload was read just before.
           * Cond1 will happen when there are no more packets to read from the buffer.
           * After that, we will wait for new packets and for the FIFOP pin to go low, and then read
           * m_bytes_left = 127 bytes. If this buffer size was decreased to 64 for instance, we could
           * read packets as they are received.
           * This whole theory explains why we only receive one copy of packets. When we're busy, we can
           * only receive around two packets = 57*2 bytes in the buffer, which means we don't get all
           * the duplicate packets. We can however get many acks since they're just 5 bytes.
           */
          m_bytes_left -= rxFrameLength + 1;
          //call EventFramework.trace_special_event(rxFrameLength);
          //call EventFramework.trace_special_event(m_bytes_left);
        }
        
        if(rxFrameLength <= MAC_PACKET_SIZE) {
          if(rxFrameLength > 0) {
            if(rxFrameLength > SACK_HEADER_LENGTH) {
                // This packet has an FCF byte plus at least one more byte to read
                call RXFIFO.continueRead(buf + 1, SACK_HEADER_LENGTH);
              } else {
              // This is really a bad packet, skip FCF and get it out of here.
              // Happens with the ACKs we receive, why?
              m_state = S_RX_PAYLOAD;
              call RXFIFO.continueRead(buf + 1, rxFrameLength);
            }

          } else {
            // Length == 0; start reading the next packet
            atomic receivingPacket = FALSE;
            call CSN.set();
            call SpiResource.release();
            call EventFramework.trace_event(45);
            waitForNextPacket();
          }
          
          // PEUSTART, it might be needed more generally, outside this if statement
          // ack

          call EventFramework.trace_event(5);
        } else {
          // Length is too large; we have to flush the entire Rx FIFO
          flush();
        }
      }
      break;
      
    case S_RX_FCF:
      m_state = S_RX_PAYLOAD;
      
      /*
       * The destination address check here is not completely optimized. If you 
       * are seeing issues with dropped acknowledgements, try removing
       * the address check and decreasing SACK_HEADER_LENGTH to 2.
       * The length byte and the FCF byte are the only two bytes required
       * to know that the packet is valid and requested an ack.  The destination
       * address is useful when we want to sniff packets from other transmitters
       * while acknowledging packets that were destined for our local address.
       */
      // This doesn't happen for us. We use blip and need hardware acks.
      if(call CC2420Config.isAutoAckEnabled() && !call CC2420Config.isHwAutoAckDefault()) {
        if (((( header->fcf >> IEEE154_FCF_ACK_REQ ) & 0x01) == 1)
            && ((header->dest == call CC2420Config.getShortAddr())
                || (header->dest == AM_BROADCAST_ADDR))
            && ((( header->fcf >> IEEE154_FCF_FRAME_TYPE ) & 7) == IEEE154_TYPE_DATA)) {
          // CSn flippage cuts off our FIFO; SACK and begin reading again
          call CSN.set();
          call CSN.clr();
          call SACK.strobe();
          call CSN.set();
          call CSN.clr();
	  call RXFIFO.beginRead(buf + 1 + SACK_HEADER_LENGTH,
				rxFrameLength - SACK_HEADER_LENGTH);

          return;
        }
      }
      // Didn't flip CSn, we're ok to continue reading.
      // FIGURE OUT WHAT HAPPENS HERE WHEN BUFFER SIZE IS JUST 1, AND HOW IT CAN GET THERE
      call RXFIFO.continueRead(buf + 1 + SACK_HEADER_LENGTH, 
			       rxFrameLength - SACK_HEADER_LENGTH);
      
      // PEUSTART, it might be needed more generally, outside this if statement
      call EventFramework.trace_event(8);
      break;

    case S_RX_PAYLOAD:
      call CSN.set();
      
      if(!m_missed_packets) {
        // Release the SPI only if there are no more frames to download
        call SpiResource.release();
      }
      
      //new packet is buffered up, or we don't have timestamp in fifo, or ack
      if ( ( m_missed_packets && call FIFO.get() ) || !call FIFOP.get()
            || !m_timestamp_size
            || rxFrameLength <= 10) {
        call PacketTimeStamp.clear(m_p_rx_buf);
      }
      else {
          if (m_timestamp_size==1)
            call PacketTimeStamp.set(m_p_rx_buf, m_timestamp_queue[ m_timestamp_head ]);
          m_timestamp_head = ( m_timestamp_head + 1 ) % TIMESTAMP_QUEUE_SIZE;
          m_timestamp_size--;

          if (m_timestamp_size>0) {
            call PacketTimeStamp.clear(m_p_rx_buf);
            m_timestamp_head = 0;
            m_timestamp_size = 0;
          }
      }

      // We may have received an ack that should be processed by Transmit
      // buf[rxFrameLength] >> 7 checks the CRC
      if ( ( buf[ rxFrameLength ] >> 7 ) && rx_buf ) {
        uint8_t type = ( header->fcf >> IEEE154_FCF_FRAME_TYPE ) & 7;
        //if (!call FIFO.get() && !call FIFOP.get())
        //  printf("Packet succeeded CRC check despite RXFIFO overflow\n");
        // Whenever this happens with our configuration, the function returns right below
        signal CC2420Receive.receive( type, m_p_rx_buf );

        if ( type == IEEE154_TYPE_DATA ) {
          // Task enqueuing
          call Leds.led1Toggle();
          call EventFramework.trace_event(140);
          post receiveDone_task();
          // SRVQUEUE ENQUEUE HIRQEXIT
          call EventFramework.trace_event(11);
          /*{
            int i;
            printf("Packet passes CRC check\n");
            for (i = 0; i < 117; ++i) {
              if (i < 35)
                printf("%u", buf[i]);
              else
                printf("%c", buf[i]);
            }
            printf("\n");
          }*/
          return;
        }
        // IF ACK, HIRQEXIT
        // This also happens at certain high pps'. On real mote, it happens at 10000 µs 22 bytes.
        call Leds.led0Toggle();
        waitForNextPacket();
        call EventFramework.trace_event(30);
      } else {
        /*int i;
        printf("Packet with seqno %u fails CRC check\n", (call CC2420PacketBody.getHeader(m_p_rx_buf))->dsn);
        for (i = 0; i < 128; ++i) {
          if (i < 35)
            printf("%u", buf[i]);
          else if (i == 35) {
            printf("\n%c", buf[i]);
          } else {
            printf("%c", buf[i]);
          }
        }
        printf("\ndone\n");*/
        //call EventFramework.trace_special_event(buf[110]);
        //call EventFramework.trace_special_event((call CC2420PacketBody.getHeader(m_p_rx_buf))->dsn);
        //call EventFramework.trace_special_event(rxFrameLength);
        //call EventFramework.trace_special_event(buf[ rxFrameLength ] >> 7); // This one is 0
        //call EventFramework.trace_special_event(rx_buf);
        waitForNextPacket();
      }
      call EventFramework.trace_event(132);

      // The below statement was uncommented. However, to end the ack HIRQ above, we added the waitForNextPacket calls above to avoid
      // additional if-statements to check if the packet was an ack.
      // waitForNextPacket();
      
      // Only receiveDoneAckPayload comes here
      break;

    default:
      atomic receivingPacket = FALSE;
      call CSN.set();
      call SpiResource.release();
      break;
      
    }
    if (old_m_state == S_RX_LENGTH) {
      call EventFramework.trace_event(6);
    } else if (old_m_state == S_RX_FCF)
      call EventFramework.trace_event(9);
  }

  async event void RXFIFO.writeDone( uint8_t* tx_buf, uint8_t tx_len, error_t error ) {
  }  
  
  /***************** Tasks *****************/
  /**
   * Fill in metadata details, pass the packet up the stack, and
   * get the next packet.
   */
  task void receiveDone_task() {
    cc2420_metadata_t* metadata = call CC2420PacketBody.getMetadata( m_p_rx_buf );
    cc2420_header_t* header = call CC2420PacketBody.getHeader( m_p_rx_buf);
    uint8_t length = header->length;
    uint8_t tmpLen __DEPUTY_UNUSED__ = sizeof(message_t) - (offsetof(message_t, data) - sizeof(cc2420_header_t));
    uint8_t* COUNT(tmpLen) buf = TCAST(uint8_t* COUNT(tmpLen), header);
    int i;
    metadata->crc = buf[ length ] >> 7;
    metadata->lqi = buf[ length ] & 0x7f;
    metadata->rssi = buf[ length - 1 ];

    if (passesAddressCheck(m_p_rx_buf) && length >= CC2420_SIZE) {
#ifdef CC2420_HW_SECURITY
      if(securityOn == 1){
        if(m_missed_packets > 0){
          m_missed_packets --;
        }
        if(authentication){
          length -= micLength;
        }
      }
      micLength = 0;
      securityOn = 0;
      authentication = 0;
#endif
      m_p_rx_buf = signal Receive.receive( m_p_rx_buf, m_p_rx_buf->data,
					   length - CC2420_SIZE);
    }
    atomic receivingPacket = FALSE;
    // Below is a new service
    waitForNextPacket();
    call EventFramework.trace_event(241);
  }

  /****************** CC2420Config Events ****************/
  event void CC2420Config.syncDone( error_t error ) {
  }

  /****************** Functions ****************/
  /**
   * Attempt to acquire the SPI bus to receive a packet.
   */
  void beginReceive() {
    // This function takes 9-11 clock cycles, so must be checked further. 
    m_state = S_RX_LENGTH;
    atomic receivingPacket = TRUE;
    if(call SpiResource.isOwner()) {
      receive();
    
    // SpiResource.immediateRequest is what brings +variable clock ticks, +-20 ticks.
    } else if (call SpiResource.immediateRequest() == SUCCESS) {
      // This occurs mostly under normal circumstances.
      receive();
    } else {
      call SpiResource.request();
    }

  }
  
  /**
   * Flush out the Rx FIFO
   */
  void flush() {
    //printf("FLUSHING\n");
    call EventFramework.trace_event(135);
#ifdef CC2420_HW_SECURITY
    flush_flag = 0;
    pos =0;
    packetLength =0;
    micLength = 0;
    securityOn = 0;
    authentication = 0;
#endif
    reset_state();

    call CSN.set();
    call CSN.clr();
    call SFLUSHRX.strobe();
    call SFLUSHRX.strobe();
    call CSN.set();
    call SpiResource.release();
    waitForNextPacket();
  }
  
  /**
   * The first byte of each packet is the length byte.  Read in that single
   * byte, and then read in the rest of the packet.  The CC2420 could contain
   * multiple packets that have been buffered up, so if something goes wrong, 
   * we necessarily want to flush out the FIFO unless we have to.
   */
  void receive() {
    // Events record 8 clock cycles for this function all the time (only one test).
    // Strangely doesn't seem to finish before another call starts sometimes. It might
    // be due to the call to CSN.clr().

	call EventFramework.trace_event(131);
    call CSN.clr();
    call RXFIFO.beginRead( (uint8_t*)(call CC2420PacketBody.getHeader( m_p_rx_buf )), 1 );
  }


  /**
   * Determine if there's a packet ready to go, or if we should do nothing
   * until the next packet arrives
   * @param pid, parameter that gets used as an offset for the tracing framework. This is to handle different
   *             PIDs calling the same function. It's unfortunate that we have to do it this way, but it works.
   *             PIDs 1-6 can call this function, which means SRVENTRY requires to occupy 6 event IDs, and there
   *             are two different SRVEXIT traces needed, which both require 6 unique event IDs. That means that
   *             this function requires to occupy 18 event IDs.
   */
  void waitForNextPacket() {


    // Called 11 times when 11 packets are received by mote 2 through Radio messages.
    // Either no more packets are awaiting, or there are packet awaiting and beginReceive
    // is called again. After that, this function is called from the readDone event again.

    atomic {
      if ( m_state == S_STOPPED ) {
        call SpiResource.release();
        // This never seems to happen. The mote has to be stopped for it to happen.
        return;
      }
      
      atomic receivingPacket = FALSE;

      /*
       * The FIFOP pin here is high when there are 0 bytes in the RX FIFO
       * and goes low as soon as there are bytes in the RX FIFO.  The pin
       * is inverted from what the datasheet says, and its threshold is 127.
       * Whenever the FIFOP line goes low, as you can see from the interrupt
       * handler elsewhere in this module, it means we received a new packet.
       * If the line stays low without generating an interrupt, that means
       * there's still more data to be received.
       */

      if ( ( m_missed_packets && call FIFO.get() ) || !call FIFOP.get() ) {
        // A new packet is buffered up and ready to go
        if ( m_missed_packets ) {
          m_missed_packets--;
        }
#ifdef CC2420_HW_SECURITY
	call SpiResource.release();
	m_state = S_RX_DEC;
  beginDec();
#else
	beginReceive();
#endif

      } else {
        // Wait for the next packet to arrive
        m_state = S_STARTED;
        m_missed_packets = 0;
        call SpiResource.release();
      }
    }

  }
  
  /**
   * Reset this component
   */
  void reset_state() {
    m_bytes_left = RXFIFO_SIZE;
    atomic receivingPacket = FALSE;
    m_timestamp_head = 0;
    m_timestamp_size = 0;
    m_missed_packets = 0;
  }

  /**
   * @return TRUE if the given message passes address recognition
   */
  bool passesAddressCheck(message_t *msg) {
    cc2420_header_t *header = call CC2420PacketBody.getHeader( msg );
    int mode = (header->fcf >> IEEE154_FCF_DEST_ADDR_MODE) & 3;
    ieee_eui64_t *ext_addr;  

    if(!(call CC2420Config.isAddressRecognitionEnabled())) {
      return TRUE;
    }

    if (mode == IEEE154_ADDR_SHORT) {
      return (header->dest == call CC2420Config.getShortAddr()
              || header->dest == IEEE154_BROADCAST_ADDR);
    } else if (mode == IEEE154_ADDR_EXT) {
      ieee_eui64_t local_addr = (call CC2420Config.getExtAddr());
      ext_addr = TCAST(ieee_eui64_t* ONE, &header->dest);
      return (memcmp(ext_addr->data, local_addr.data, IEEE_EUI64_LENGTH) == 0);
    } else {
      /* reject frames with either no address or invalid type */
      return FALSE;
    }
  }

}
