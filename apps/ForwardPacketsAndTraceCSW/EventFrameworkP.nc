
typedef struct static_event {
    uint8_t eid;
    uint32_t cycles;
} static_event;

#define NUMBER_EVENTS 700
static_event events[NUMBER_EVENTS];
uint32_t nr_events = 0;


module EventFrameworkP {
  provides {
    interface EventFramework;
  }
  uses {
    interface Counter<TMicro, uint32_t> as AccurateTimer;
    interface Counter<TMilli, uint32_t> as MillisecondTimer;
    interface Putchar;
    interface UartByte;
    interface BusyWait<TMicro, uint32_t> as BusyWait;
    interface LogWrite;
    interface LogRead;
  }

} implementation {

  uint8_t event_index = 0;
  uint8_t byte_index = 0;
  uint8_t bytes_to_send[5];
  
  uint8_t printing = 0;

  command void EventFramework.print_events() {
    int i;
    //if (TOS_NODE_ID == 2)
    //  return;
    
    for (i = 0; i < nr_events; ++i) {
      #if 0
        printf("%lu - %u\n", events[i].cycles, events[i].eid);
      #else  	
        uint8_t b1 = events[i].cycles & 0xFF;
        uint8_t b2 = (events[i].cycles & 0xFF00) >> 8;
        uint8_t b3 = (events[i].cycles & 0xFF0000) >> 16;
        uint8_t b4 = (events[i].cycles & 0xFF000000) >> 24;
        //printf("%c%c%c%c%c", events[i].eid, b1, b2, b3, b4);
        printf("%c", events[i].eid);
        call BusyWait.wait(2000);
        printf("%c", b1);
        call BusyWait.wait(2000);
        printf("%c", b2);
        call BusyWait.wait(2000);
        printf("%c", b3);
        call BusyWait.wait(2000);
        printf("%c", b4);
        call BusyWait.wait(2000);
      #endif
    }

	nr_events = 0;
    //memset(events, 0, sizeof(static_event)*NUMBER_EVENTS);
  }
  
  async event void AccurateTimer.overflow() {}

  async event void MillisecondTimer.overflow() {}

  #define REAL_MOTE_TRACING 1
  #define INSTANT_TRACING 0
  #define FLASH_TRACING 0
  
  void real_saving_event() {
  	++nr_events;
  	if (nr_events == NUMBER_EVENTS-1 && !printing) {
  		atomic {
	  		printing = 1;
	  	//	call EventFramework.trace_event(98);  // Before printing traces
	        call EventFramework.print_events();
	    //    call EventFramework.trace_event(99);  // After printing traces
	    	printing = 0;
    	}
    }
  }
  
  void cooja_instant_tracing(uint8_t eid) {
	  printf("%u\n", eid);  // Cooja tracing overhead = 350 µs, how?
  }
  
  void real_instant_tracing(uint8_t eid) {
  	printf("%c", eid);
  }
  
  void trace(uint8_t eid, uint32_t time) {
  
  	#if FLASH_TRACING
  	if (eid != 0 && eid != 23)
  		return;
  	events[0].eid = eid;
  	events[0].cycles = time;
  	call LogWrite.append(&events[0], sizeof(static_event));
    #elif REAL_MOTE_TRACING
    #if INSTANT_TRACING
    real_instant_tracing(eid);
    #else
    events[nr_events].eid = eid;
    events[nr_events].cycles = time;
    real_saving_event();
    #endif
    #else
    cooja_instant_tracing(eid);
    #endif
  }

  // Function almost identical to the trace_event command. 
  // The difference is that we might want to allow traces here
  // that we ignore in trace_event
  async command void EventFramework.trace_special_event(uint8_t eid) {
    if (TOS_NODE_ID == 1 || TOS_NODE_ID == 3 || printing)
  	  return;
  	trace(eid, call AccurateTimer.get());
  }

  async command void EventFramework.trace_event(uint8_t eid) {
    if (TOS_NODE_ID == 1 || TOS_NODE_ID == 3 || (eid != 131 && eid != 133 /* && eid != 145 && eid != 140 && eid != 132 && eid != 135 && eid != 134 && eid != 166 && eid != 150*/) || printing)
  	  return;
  	trace(eid, call AccurateTimer.get());
  }
  
  async command void EventFramework.trace_event_custom_time(uint8_t eid, uint32_t time) {
    return;

  	trace(eid, time);
  }
 
  
  event void LogWrite.appendDone(void* buf, storage_len_t len, bool recordsLost, error_t err) {
  }

  event void LogWrite.syncDone(error_t err) { }

  event void LogWrite.eraseDone(error_t err) { }
  
  event void LogRead.readDone(void* buf, storage_len_t len, error_t error) {
  }
  
  event void LogRead.seekDone(error_t err) { }
}
