
#include "StorageVolumes.h"

configuration EventFrameworkC {
	provides interface EventFramework;
} implementation {
	components MainC;
	components EventFrameworkP;
	components CounterMicro32C;
	components SerialPrintfC;

	EventFramework = EventFrameworkP;
 
 	components CounterMilli32C;
  	EventFrameworkP.AccurateTimer -> CounterMicro32C;
  	EventFrameworkP.MillisecondTimer -> CounterMilli32C;
	EventFrameworkP.Putchar -> SerialPrintfC;

	components PlatformSerialC;
	EventFrameworkP.UartByte -> PlatformSerialC;
	components new BusyWaitCounterC(TMicro, uint32_t);
	BusyWaitCounterC.Counter -> CounterMicro32C;
	EventFrameworkP.BusyWait -> BusyWaitCounterC;
	components new LogStorageC(VOLUME_DELUGE3, FALSE);
    EventFrameworkP.LogRead -> LogStorageC.LogRead;
    EventFrameworkP.LogWrite -> LogStorageC.LogWrite;
}
