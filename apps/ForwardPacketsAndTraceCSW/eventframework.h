#ifndef EVENTFRAMEWORKH
#define EVENTFRAMEWORKH

#include "blip_printf.h"

struct event {
	uint8_t event_class;
	char event_name[32];
	uint32_t time;
	char function_signature[32];
};

#define MAX_EVENTS 1
struct event events[MAX_EVENTS];
uint16_t event_index = 0;

/*
 * This function prints out a specific event with the provided data.
 * Format of event:
 * - time: uint16_t as difference between current and previous time?
 * - That would save a lot of space and would be easy to implement, we simply need a global
 * - variable to keep the previous time, and then the listener can sum the differences.
*/
void print_event(uint8_t event_class, char *event_name, uint32_t time, char *function_signature, uint8_t do_print) {
	if (TOS_NODE_ID == 2) {
		struct event *new_event;
		if (event_index == MAX_EVENTS || do_print) {
			int i;
			for (i = 0; i < event_index; ++i)
				printf("Event c=%d - %s, t=%lu 32khz, l=%s\n", events[i].event_class, events[i].event_name, events[i].time, events[i].function_signature);
			event_index = 0;
			if (do_print)
				printf("Willfully printing Events\n");
		}

		new_event = &events[event_index];
		new_event->event_class = event_class;
		strcpy(new_event->event_name, event_name);
		new_event->time = time;
		strcpy(new_event->function_signature, function_signature);
		++event_index;
		//printf("Event c=%d - %s, t=%lu 32khz, l=%s\n", event_class, event_name, time, function_signature);
	}
}

#endif