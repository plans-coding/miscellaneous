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

## Calibration Input

Measure the voltage at A0 for different temperatures on the probe. We will use this data when we configure the circiut in Esphome.

| Temperature measured by a reference thermometer | Voltage $V_{A0}$ measured at A0 | Resistance $R_{NTC}$ over thermistor (calculated) |
|-|-|-|
| 16 °C | 0.67480 V | 25.704 kOhm |
| 23 °C | 0.62500 V | 23.364 kOhm |
| 57 °C | 0.35938 V | 12.221 kOhm |

The resistance over the thermistor is (read more about [voltage divider](https://en.wikipedia.org/wiki/Voltage_divider#General_case))

$$R_{NTC} = \frac{ V_{3.3} * R_{100} }{ V_{3.3} - V_{A0} } = \frac{ 3.3*10^5 }{ 3.3 - V_{A0} }$$

Some guides mention [Steinhart–Hart equation](https://en.wikipedia.org/wiki/Steinhart%E2%80%93Hart_equation). Since Esphome handle this we do not need to use the equation on our own.

## Esphome

Navigate to your Esphome installation, e.g. http://localhost:6052/ and click **New Device**.

### Reading
> [!NOTE]
> The variable resistor (i.e. our thermistor) is close to GND in the circuit above => DOWNSTREAM

* https://esphome.io/components/sensor/resistance
* https://esphome.io/components/sensor/ntc.html

In our case, due to the high resistance, the current through the thermistor is very small. I guess self-heating does not need to be taken into account.

### Crucial part of the Yaml Configuration
```
sensor:
  - platform: ntc
    sensor: resistance_ntc
    calibration:
      - 25.704kOhm -> 16°C
      - 23.364kOhm -> 23°C
      - 12.221kOhm -> 57°C
    name: "Probe Temperature"
    unit_of_measurement: "°C"
    accuracy_decimals: 1

  - platform: resistance
    id: resistance_ntc
    sensor: a0_voltage
    configuration: DOWNSTREAM
    resistor: 100kOhm
    name: "Probe Resistance"

  - platform: adc
    id: a0_voltage
    pin: A0
    update_interval: 5s
    name: "A0 Voltage"
```
