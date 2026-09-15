// Distribution Process Logic (OpenPLC v4 ST project)
// Manages the distribution pump and discharge pressure.
//
// Build:  plc/build.sh   (compiled by STruC++ into plc/programs/distribution/program.zip)
// Register map (Modbus Holding Registers):
//   %QW0: Distribution pump command (0 = off, 1 = on)
//   %QW1: Discharge pressure (bar) - process state
//   %QW2: Pump speed (%)
//   %QW5: Pump runtime (hours) - accumulated
//   %QW6: Pressure alarm (0 = normal, 1 = low pressure with pump on)

PROGRAM MAIN
VAR
    PumpCommand   AT %QW0 : UINT;
    DischargePres AT %QW1 : UINT;
    PumpSpeed     AT %QW2 : UINT;
    PumpRuntime   AT %QW5 : UINT;
    PressureAlarm AT %QW6 : UINT;
END_VAR

// Process simulation: pressure follows pump state
IF PumpCommand = 1 THEN
    DischargePres := DischargePres + 1;
    PumpRuntime := PumpRuntime + 1;
    PumpSpeed := 80;
ELSE
    IF DischargePres >= 2 THEN
        DischargePres := DischargePres - 2;
    ELSE
        DischargePres := 0;
    END_IF;
    PumpSpeed := 0;
END_IF;

IF DischargePres > 10 THEN
    DischargePres := 10;
END_IF;

// Alarm: pump running but no pressure = failed pump / sabotage indicator
IF PumpCommand = 1 AND DischargePres < 2 THEN
    PressureAlarm := 1;
ELSE
    PressureAlarm := 0;
END_IF;

END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK Task0(INTERVAL := T#500ms, PRIORITY := 0);
    PROGRAM Inst0 WITH Task0 : MAIN;
  END_RESOURCE
END_CONFIGURATION
