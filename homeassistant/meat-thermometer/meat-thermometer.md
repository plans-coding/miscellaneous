# Meat Thermometer Sensor

## Hardware Requirements
* A probe from [Ikea Fantast](https://www.ikea.com/se/sv/p/fantast-stektermometer-timer-digital-svart-20103016/) meat thermometer
* A microcontroller board like [Wemos D1 mini version 4](https://www.wemos.cc/en/latest/d1/d1_mini.html)
* A resistor of 100 kOhm
* Some wires

## Circuit Diagram
The probe from Ikea Fantast is rendered as a thermistor with NTC (Negative Temperature Coefficient) in the diagram below

![img](circuit.svg)

The 3.3 V, A0 and GND are connected to the corresponding pins on the D1 mini.

## Calibration

| Temperature measured by a reference thermometer | Voltage measured at A0 |
|-|-|
| 16 °C | 0.67480 |
| 23 °C | 0.62500 |
| 57 °C | 0.35938 |
