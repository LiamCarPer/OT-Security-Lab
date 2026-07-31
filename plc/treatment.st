// Treatment Process Logic (OpenPLC ST)
// Controls chemical dosing based on incoming flow.
// Register map (Modbus Holding Registers):
//   %QW0: Inlet flow (m3/h) - process state
//   %QW1: Dosing pump command (0 = off, 1 = on)
//   %QW2: Dosing rate (%)
//   %QW5: Residual chlorine (ppm) - process state
//   %QW6: Dosing alarm (0 = normal, 1 = out-of-range)

// Process simulation: chlorine residual decays over time
%QW5 := %QW5 - 1;
IF %QW5 < 0 THEN
    %QW5 := 0;
END_IF;

// Dosing control: pump engages when flow is present and chlorine is low
IF %QW0 > 0 AND %QW5 < 20 THEN
    %QW1 := 1;
    %QW2 := 50;
ELSE
    IF %QW5 >= 40 THEN
        %QW1 := 0;
        %QW2 := 0;
    END_IF;
END_IF;

// Out-of-range chlorine is a process alarm
IF %QW5 > 60 OR (%QW0 > 0 AND %QW5 = 0) THEN
    %QW6 := 1;
ELSE
    %QW6 := 0;
END_IF;
