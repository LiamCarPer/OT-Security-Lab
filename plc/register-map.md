# PLC Register Map (Modbus/TCP)

Canonical map shared by the PLC logic (`plc/*.st`), the detection rules
(`detection/rules/`), the Scada-LTS HMI, and the compliance tests. Any change
here must be reflected in all four.

## 1. Address translation

OpenPLC maps located variables directly onto the Modbus data model:

| IEC 61131-3 location | Modbus table      | Modbus address |
| :------------------- | :---------------- | :------------- |
| `%QWn`               | Holding Register  | `n` (0-based)  |
| `%MWn`               | Holding Register  | `1024 + n`     |

Only `%QW` is used by this lab, so `%QWn` == holding register `n`. All values
are unsigned 16-bit integers (`0..65535`, function code 3 read / 6 and 16
write). Unit ID / slave ID is `1` on every PLC.

## 2. Intake — PLC-01 (`172.21.0.10`)

| Register | IEC    | Name                | Access | Meaning                                   |
| :------- | :----- | :------------------ | :----- | :---------------------------------------- |
| HR 0     | `%QW0` | Inlet valve command | RW     | `0` = closed, `1` = open                  |
| HR 1     | `%QW1` | Intake pump speed   | RW     | Percent (`0..100`)                        |
| HR 5     | `%QW5` | Tank level          | RO     | Percent (`0..100`) — physics-aware source |
| HR 6     | `%QW6` | Overflow interlock  | RO     | `0` = normal, `1` = interlock tripped     |

The physics-aware IDS rule (`process_safety_violation.py`) shadows HR 5 and
raises `PROCESS_SAFETY_VIOLATION` when HR 0 is written to `1` while HR 5 > 90.

## 3. Treatment — PLC-02 (`172.21.0.11`)

| Register | IEC    | Name              | Access | Meaning                             |
| :------- | :----- | :---------------- | :----- | :---------------------------------- |
| HR 0     | `%QW0` | Inlet flow        | RO     | m3/h                                |
| HR 1     | `%QW1` | Dosing pump       | RW     | `0` = off, `1` = on                 |
| HR 2     | `%QW2` | Dosing rate       | RW     | Percent                             |
| HR 5     | `%QW5` | Residual chlorine | RO     | ppm                                 |
| HR 6     | `%QW6` | Dosing alarm      | RO     | `0` = normal, `1` = out-of-range    |

## 4. Distribution — PLC-03 (`172.21.0.12`)

| Register | IEC    | Name               | Access | Meaning                                  |
| :------- | :----- | :----------------- | :----- | :--------------------------------------- |
| HR 0     | `%QW0` | Distribution pump  | RW     | `0` = off, `1` = on                      |
| HR 1     | `%QW1` | Discharge pressure | RO     | bar                                      |
| HR 2     | `%QW2` | Pump speed         | RW     | Percent                                  |
| HR 5     | `%QW5` | Pump runtime       | RO     | Accumulated hours                        |
| HR 6     | `%QW6` | Pressure alarm     | RO     | `0` = normal, `1` = pump on but no pressure |
