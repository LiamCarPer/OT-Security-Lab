// Distribution Process Logic (OpenPLC ST)
// Manages the distribution pump and discharge pressure.
// Register map (Modbus Holding Registers):
//   %QW0: Distribution pump command (0 = off, 1 = on)
//   %QW1: Discharge pressure (bar) - process state
//   %QW2: Pump speed (%)
//   %QW5: Pump runtime (hours) - accumulated
//   %QW6: Pressure alarm (0 = normal, 1 = low pressure with pump on)

// Process simulation: pressure follows pump state
IF %QW0 = 1 THEN
    %QW1 := %QW1 + 1;
    %QW5 := %QW5 + 1;
ELSE
    %QW1 := %QW1 - 2;
END_IF;

IF %QW1 > 10 THEN
    %QW1 := 10;
END_IF;
IF %QW1 < 0 THEN
    %QW1 := 0;
END_IF;

// Alarm: pump running but no pressure = failed pump / sabotage indicator
IF %QW0 = 1 AND %QW1 < 2 THEN
    %QW6 := 1;
ELSE
    %QW6 := 0;
END_IF;
