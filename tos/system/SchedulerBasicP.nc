// $Id: SchedulerBasicP.nc,v 1.11 2010-06-29 22:07:56 scipio Exp $

/*
 * Copyright (c) 2000-2003 The Regents of the University  of California.  
 * All rights reserved.
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
 * - Neither the name of the University of California nor the names of
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
 * Copyright (c) 2002-2003 Intel Corporation
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached INTEL-LICENSE     
 * file. If you do not find these files, copies can be found by writing to
 * Intel Research Berkeley, 2150 Shattuck Avenue, Suite 1300, Berkeley, CA, 
 * 94704.  Attention:  Intel License Inquiry.
 */

/**
 * SchedulerBasicP implements the default TinyOS scheduler sequence, as
 * documented in TEP 106.
 *
 * @author Philip Levis
 * @author Cory Sharp
 * @date   January 19 2005
 */

#include <hardware.h>
#include <stdio.h>

module SchedulerBasicP @safe() {
  provides interface Scheduler;
  provides interface TaskBasic[uint8_t id];
  uses interface McuSleep;
  uses interface EventFramework;
}
implementation
{
  enum
  {
    NUM_TASKS = uniqueCount("TinySchedulerC.TaskBasic"),
    NO_TASK = 255,
  };

  uint8_t m_head;
  uint8_t m_tail;
  uint8_t m_next[NUM_TASKS];

  // Helper functions (internal functions) intentionally do not have atomic
  // sections.  It is left as the duty of the exported interface functions to
  // manage atomicity to minimize chances for binary code bloat.

  // move the head forward
  // if the head is at the end, mark the tail at the end, too
  // mark the task as not in the queue
  inline uint8_t popTask()
  {
    //call EventFramework.post_event(1, "SRV Start", "SchedulerBasicP.popTask", "");
    if( m_head != NO_TASK )
    {
      uint8_t id = m_head;
      m_head = m_next[m_head];
      if( m_head == NO_TASK )
      {
	m_tail = NO_TASK;
      }
      m_next[id] = NO_TASK;
      //call EventFramework.post_event(1, "SRV Stop", "SchedulerBasicP.popTask", "");
      return id;
    }
    else
    {
      //call EventFramework.post_event(1, "SRV Stop", "SchedulerBasicP.popTask", "NO_TASK");
      return NO_TASK;
    }
  }
  
  bool isWaiting( uint8_t id )
  {
    return (m_next[id] != NO_TASK) || (m_tail == id);
  }

  bool pushTask( uint8_t id )
  {
    //call EventFramework.post_event(1, "Pushing task", "SchedulerBasicP.pushTask", "");
    if( !isWaiting(id) )
    {
      if( m_head == NO_TASK )
      {
	m_head = id;
	m_tail = id;
      }
      else
      {
	m_next[m_tail] = id;
	m_tail = id;
      }
      //call EventFramework.post_event(1, "SRV Stop", "SchedulerBasicP.pushTask", "");
      return TRUE;
    }
    else
    {
      //call EventFramework.post_event(1, "SRV Stop", "SchedulerBasicP.pushTask", "");
      return FALSE;
    }
  }
  
  command void Scheduler.init()
  {
    atomic
    {
      memset( (void *)m_next, NO_TASK, sizeof(m_next) );
      m_head = NO_TASK;
      m_tail = NO_TASK;
    }
  }
  
  command bool Scheduler.runNextTask()
  {
    uint8_t nextTask;
    //call EventFramework.post_event(1, "SRV Start", "SchedulerBasicP.runNextTask", "");
    atomic
    {
      nextTask = popTask();
      if( nextTask == NO_TASK )
      {
        //call EventFramework.post_event(1, "SRV Stop", "SchedulerBasicP.runNextTask", "");
	return FALSE;
      }
    }
    signal TaskBasic.runTask[nextTask]();
    //call EventFramework.post_event(1, "SRV Stop", "SchedulerBasicP.runNextTask", "");
    return TRUE;
  }

  //uint32_t cnt = 0;
  uint8_t scheduler_taskloop_addr;
  command void Scheduler.taskLoop()
  {
    // LOOPSTART taskloop
    call EventFramework.trace_event(33);
    for (;;)
    {
      uint8_t nextTask;

      atomic
      {
          uint8_t no_task = (uint8_t)((nextTask = popTask()) == NO_TASK);
          /*if (no_task)
            call EventFramework.trace_event(35); // QUEUECOND - LOOPSTART
          else
            call EventFramework.trace_event(34); // QUEUECOND*/
        	while (no_task)
        	{
            // If we don't sleep, we can't be pre-empted. The preemption only works if we go to sleep.
            // But then how do we preempt for readDonePayload_ack to sendDone? Do we temporarily sleep there?
            //printf("b\n");
            //cnt = 0;
            //while (cnt++ < 100000)
            //  call EventFramework.trace_event(10);
            //printf("Sleeping\n");
            //printf("Waking\n");
            //call EventFramework.trace_event(96);
            call McuSleep.sleep();
            //call EventFramework.trace_event(97);
            //printf("a\n");
            no_task = (uint8_t)((nextTask = popTask()) == NO_TASK);
            /*if (no_task)
              call EventFramework.trace_event(36); // WAKEUP - QUEUECOND - LOOPRSTART
            else
              call EventFramework.trace_event(37); // WAKEUP - QUEUECOND - LOOPSTOP*/
          }
      }
      
      call EventFramework.trace_event(39); // CTXSW DEQUEUE SRVQUEUE task_queue
      signal TaskBasic.runTask[nextTask]();
      //call EventFramework.post_event(4, "Loop Stop", "SchedulerBasicP.taskLoop", "");
      call EventFramework.trace_event(38); // LOOPRSTART
    }
  }

  /**
   * Return SUCCESS if the post succeeded, EBUSY if it was already posted.
   */
  
  async command error_t TaskBasic.postTask[uint8_t id]()
  {
    // Task enqueuing, currently breaks the system because event framework uses tasks
    //call EventFramework.post_detailed_event_0(5, 'e', (uint16_t)&__FUNCTION__);
    atomic { return pushTask(id) ? SUCCESS : EBUSY; }
  }

  default event void TaskBasic.runTask[uint8_t id]()
  {
  }
}

