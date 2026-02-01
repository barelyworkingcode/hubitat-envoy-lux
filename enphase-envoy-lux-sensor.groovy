/**
 *  Enphase Envoy Lux Sensor - Child Device
 *
 *  Copyright 2025
 */

metadata {
    definition (name: "Enphase Envoy Lux Sensor", namespace: "custom", author: "Custom") {
        capability "IlluminanceMeasurement"
        capability "Sensor"
        capability "Refresh"

        attribute "powerValue", "number"
        attribute "sensorType", "string"
    }
}

def refresh() {
    parent?.refresh()
}

def installed() {
    log.info "Enphase Envoy Lux Sensor installed: ${device.displayName}"
}

def updated() {
    log.info "Enphase Envoy Lux Sensor updated: ${device.displayName}"
}