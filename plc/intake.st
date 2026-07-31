// Intake Process Logic (OpenPLC ST)
// Simulates the water intake tank and enforces the overflow safety interlock.
// Register map (Modbus Holding Registers):
//   %QW0: Inlet Valve command (0 = closed, 1 = open)
//   %QW1: Intake pump speed (%)
//   %QW5: Tank Level (%) - process state, simulated here
//   %QW6: Interlock alarm (0 = normal, 1 = overflow interlock tripped)

// --- Process simulation: tank level dynamics ---
IF %QW0 = 1 THEN
    // Filling: level rises while the inlet valve is open
    %QW5 := %QW5 + 1;
ELSE
    // Draining: level falls when the valve is closed
    %QW5 := %QW5 - 1;
END_IF;

IF %QW5 > 100 THEN
    %QW5 := 100;
END_IF;

IF %QW5 < 0 THEN
    %QW5 := 0;
END_IF;

// --- Safety interlock (IEC 61511 SIS-style) ---
// Hard override: never allow the inlet valve to open above 90% level.
// The network-side IDS shadows this same rule for defense in depth.
IF %QW5 > 90 THEN
    %QW0 := 0;
    %QW6 := 1;
ELSE
    %QW6 := 0;
END_IF;
