// Treatment Process Logic (OpenPLC v4 ST project)
// Controls chemical dosing based on incoming flow.
//
// Build:  plc/build.sh   (compiled by STruC++ into plc/programs/treatment/program.zip)
// Register map (Modbus Holding Registers):
//   %QW0: Inlet flow (m3/h) - process state
//   %QW1: Dosing pump command (0 = off, 1 = on)
//   %QW2: Dosing rate (%)
//   %QW5: Residual chlorine (ppm) - process state
//   %QW6: Dosing alarm (0 = normal, 1 = out-of-range)

PROGRAM MAIN
VAR
    InletFlow      AT %QW0 : UINT;
    DosingPump     AT %QW1 : UINT;
    DosingRate     AT %QW2 : UINT;
    ResidualChlor  AT %QW5 : UINT;
    DosingAlarm    AT %QW6 : UINT;
END_VAR

// Process simulation: residual chlorine decays over time
IF ResidualChlor > 0 THEN
    ResidualChlor := ResidualChlor - 1;
END_IF;

// Dosing control: pump engages when flow is present and chlorine is low
IF InletFlow > 0 AND ResidualChlor < 20 THEN
    DosingPump := 1;
    DosingRate := 50;
ELSIF ResidualChlor >= 40 THEN
    DosingPump := 0;
    DosingRate := 0;
END_IF;

// Out-of-range chlorine is a process alarm
IF ResidualChlor > 60 OR (InletFlow > 0 AND ResidualChlor = 0) THEN
    DosingAlarm := 1;
ELSE
    DosingAlarm := 0;
END_IF;

END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK Task0(INTERVAL := T#500ms, PRIORITY := 0);
    PROGRAM Inst0 WITH Task0 : MAIN;
  END_RESOURCE
END_CONFIGURATION
