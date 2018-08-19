
interface EventFramework {
	async command void trace_event(uint8_t eid);
	async command void trace_special_event(uint8_t eid);
	async command void trace_event_custom_time(uint8_t eid, uint32_t time);
	command void print_events();
}
