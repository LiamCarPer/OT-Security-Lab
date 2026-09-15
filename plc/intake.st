// Intake Process Logic (OpenPLC v4 ST project)
// Simulates the water intake tank and enforces the overflow safety interlock.
//
// Build:  plc/build.sh   (compiled by STruC++ into plc/programs/intake/program.zip)
// Register map (Modbus Holding Registers):
//   %QW0: Inlet Valve command (0 = closed, 1 = open)
//   %QW1: Intake pump speed (%)
//   %QW5: Tank Level (%) - process state, simulated here
//   %QW6: Interlock alarm (0 = normal, 1 = overflow interlock tripped)

PROGRAM MAIN
VAR
    InletValve AT %QW0 : UINT;
    Pump       AT %QW1 : UINT;
    TankLevel  AT %QW5 : UINT;
    Alarm      AT %QW6 : UINT;
END_VAR

// --- Process simulation: autonomous level control ---
// A real intake station keeps the tank within an operating band. The level
// controller calls for water when the tank is low; the SIS interlock (below)
// is the independent high-high trip at 95%.
IF TankLevel < 20 THEN
    InletValve := 1;
END_IF;

IF InletValve = 1 THEN
    // Filling: level rises while the inlet valve is open
    TankLevel := TankLevel + 1;
ELSE
    // Draining: level falls when the valve is closed
    TankLevel := TankLevel - 1;
END_IF;

IF TankLevel > 100 THEN
    TankLevel := 100;
END_IF;

IF TankLevel < 0 THEN
    TankLevel := 0;
END_IF;

// --- Safety interlock (IEC 61511 SIS-style) ---
// Hard override: never allow the inlet valve to remain open above 95% level.
// The network-side IDS shadows a tighter 90% envelope for defense in depth.
IF TankLevel > 95 THEN
    InletValve := 0;
    Alarm := 1;
ELSE
    Alarm := 0;
END_IF;

END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK Task0(INTERVAL := T#500ms, PRIORITY := 0);
    PROGRAM Inst0 WITH Task0 : MAIN;
  END_RESOURCE
END_CONFIGURATION
