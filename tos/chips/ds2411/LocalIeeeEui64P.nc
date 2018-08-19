#include "PlatformIeeeEui64.h"

module LocalIeeeEui64P {
  provides {
    interface LocalIeeeEui64;
  }
  uses {
    interface ReadId48;
  }
}

implementation {
  ieee_eui64_t eui = {{0x00}};

  bool have_id = FALSE;

  command ieee_eui64_t LocalIeeeEui64.getId () {
    uint8_t buf[6] = {0};
    error_t e;

    if (!have_id) {
      // Code ahead has been changed by Espen
      // Normally, we will only assign an address if the next operation succeeds,
      // but for simulation, we simply assign an address.
      //e = call ReadId48.read(buf);
      eui.data[0] = 2;
      eui.data[1] = 0;
      eui.data[2] = 0;
      eui.data[3] = 0;
      eui.data[4] = 0;
      eui.data[5] = 0;
      eui.data[6] = 0;
      eui.data[7] = TOS_NODE_ID;

      have_id = TRUE;
    }
    return eui;
  }
}
