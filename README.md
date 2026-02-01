# Hubitat Envoy Lux

A smart home monitoring solution that integrates Enphase Envoy solar power data with Hubitat Elevation and includes authentication tools for accessing local Envoy systems.

## Overview

This project provides multiple tools for monitoring Enphase Envoy solar production systems:

1. **Hubitat Driver** - A comprehensive Groovy driver for Hubitat Elevation that provides real-time solar production monitoring
2. **Authentication Script** - A bash script that implements the complete Enphase OAuth + PKCE authentication flow (for debugging)
3. **Lux Sensor Integration** - Child devices that convert power readings to illuminance values for creative smart home automations

## Features

### 🌞 Real-time Solar Monitoring
- **Solar Production**: Current power generation from your solar panels
- **Home Consumption**: Real-time power usage of your home
- **Export Power**: Amount of power being exported back to the grid
- **Net Consumption**: Import/export balance (negative = exporting, positive = importing)

### 🔐 Advanced Authentication
- Complete OAuth 2.0 + PKCE authentication flow
- Automatic session management with 24-48 hour validity
- Intelligent re-authentication when sessions expire
- Manual session override capability
- Rate limiting to prevent account lockout

### 🏠 Smart Home Integration
- Native Hubitat Elevation integration
- Child devices for each power metric
- Lux sensor compatibility for creative automations
- Configurable scaling factors
- Real-time updates with configurable polling intervals

## How It Works

### Data Flow
1. **Authentication**: The system uses Enphase's OAuth flow to obtain a session cookie
2. **Data Retrieval**: Polls the local Envoy device at `https://envoy.lan/production.json`
3. **Data Processing**: Parses JSON response to extract key metrics:
   - `production[measurementType="production"].wNow` → Solar production
   - `consumption[measurementType="total-consumption"].wNow` → Home consumption
   - `consumption[measurementType="net-consumption"].wNow` → Net consumption/export

### Authentication Process
The authentication implements the complete Enphase OAuth flow:
1. Generate PKCE (Proof Key for Code Exchange) parameters
2. Fetch login page and extract CSRF tokens
3. Submit credentials to Enphase portal
4. Extract authorization code from callback
5. Exchange code for JWT access token
6. Exchange JWT for local session cookie

## Installation & Setup

### Prerequisites
- Hubitat Elevation hub
- Enphase Envoy system on local network
- Enphase account credentials
- Envoy accessible at `envoy.lan` or custom IP

### Hubitat Driver Installation

1. **Import Driver Code**:
   - Copy the contents of `enphase-envoy-driver-v4.groovy`
   - In Hubitat web interface, go to **Drivers Code**
   - Click **New Driver**, paste code, and **Save**

2. **Create Device**:
   - Go to **Devices** → **Add Device** → **Virtual**
   - Choose "Enphase Envoy Solar Monitor v4" as device type
   - Configure device name and save

3. **Configure Settings**:
   ```
   Envoy IP Address: envoy.lan (or your Envoy's IP)
   Enphase Username: your-enphase-account@email.com
   Enphase Password: your-enphase-password
   Poll Interval: 5 minutes (recommended)
   Scale Factor: 1000 (for lux conversion)
   Session Duration: 24 hours
   ```

4. **Create Child Devices**:
   - Click **Create Child Devices** command in device page
   - This creates separate sensors for production, consumption, and export

### Authentication Script Usage

For standalone authentication or debugging:

```bash
# Set environment variables (required)
export ENPHASE_USERNAME="your-email@example.com"
export ENPHASE_PASSWORD="your-password"
export ENVOY_HOST="envoy.lan"  # optional, defaults to envoy.lan

# Run authentication
./enphase-auth.sh
```

The script will:
- Complete the full OAuth flow
- Output the session ID
- Save session ID to `session_id.txt`
- Test access to production data

### Manual Session Testing

```bash
# Using saved session ID
curl -k -b "sessionId=$(cat session_id.txt)" "https://envoy.lan/production.json"

# Using specific session ID
curl -k -b "sessionId=YOUR_SESSION_ID" "https://envoy.lan/production.json"
```

## Configuration Options

### Hubitat Driver Settings

| Setting | Description | Default | Range |
|---------|-------------|---------|-------|
| **Envoy IP Address** | IP or hostname of Envoy | `envoy.lan` | - |
| **Enphase Username** | Account email | - | Required |
| **Enphase Password** | Account password | - | Required |
| **Poll Interval** | Update frequency | 5 minutes | 1-60 min |
| **Scale Factor** | Lux conversion divisor | 1000 | Any number |
| **Session Duration** | Assumed session validity | 24 hours | 1-72 hours |
| **Manual Session ID** | Override auto-auth | - | Optional |

### Environment Variables (Auth Script)

| Variable | Description | Required |
|----------|-------------|----------|
| `ENPHASE_USERNAME` | Enphase account email | Yes |
| `ENPHASE_PASSWORD` | Enphase account password | Yes |
| `ENVOY_HOST` | Envoy hostname/IP | No (defaults to envoy.lan) |

## Sample Data Structure

The Envoy returns data in this format (from `sample_output.json`):

```json
{
    "production": [
        {
            "type": "eim",
            "measurementType": "production",
            "wNow": 10798.302,
            "whLifetime": 42876.984
        }
    ],
    "consumption": [
        {
            "measurementType": "total-consumption",
            "wNow": 680.76
        },
        {
            "measurementType": "net-consumption",
            "wNow": -10117.541
        }
    ]
}
```

## Smart Home Automation Ideas

### Lux-Based Automations
Since the system creates lux sensors, you can create creative automations:

- **Bright = High Production**: Use solar production lux to trigger "sunny day" scenes
- **Export Notifications**: Alert when exporting significant power
- **Load Management**: Start energy-intensive devices when production is high

### Example Automations
```groovy
// Turn on pool pump when solar production > 5000W (5 lux with scale factor 1000)
if (solarProductionLux > 5) {
    poolPump.on()
}

// Send notification when exporting > 8000W
if (exportPowerLux > 8) {
    sendNotification("High solar export: ${exportPower}W")
}
```

## Troubleshooting

### Common Issues

**Authentication Failures**
- Verify credentials are correct
- Check if Envoy is accessible at specified IP
- Try manual session ID if auto-auth fails
- Check for account lockout (wait 1 hour)

**No Data Updates**
- Verify poll interval is set and > 0
- Check device logs for HTTP errors
- Ensure Envoy is responding to production.json requests
- Try refreshing device manually

**Session Expiration**
- Sessions typically last 24-48 hours
- Driver automatically re-authenticates
- Use "Clear Session" command to force re-auth
- Check session expiry time in device attributes

### Debug Logging
Enable detailed logging in device settings:
- **Enable debug logging**: Shows data parsing and HTTP details
- **Enable authentication logging**: Shows OAuth flow details

### Manual Commands
Available device commands for troubleshooting:
- **Refresh**: Force immediate data update
- **Authenticate**: Force new authentication
- **Clear Session**: Invalidate current session
- **Create Child Devices**: Recreate child sensors
- **Delete Child Devices**: Remove child sensors

## Security Considerations

- **Credentials**: Never commit credentials to version control
- **Local Network**: All data requests go to local Envoy device
- **Session Management**: Sessions are automatically managed and renewed
- **Rate Limiting**: Built-in protection against account lockout

## Development

### Project Structure
```
├── enphase-auth.sh                    # Standalone authentication script
├── enphase-envoy-driver-v4.groovy     # Main Hubitat driver
├── enphase-envoy-lux-sensor.groovy    # Child device driver
└── README.md                          # This file
```

### Testing Authentication
```bash
# Test authentication flow
./enphase-auth.sh

# Verify session works
curl -k -b "sessionId=$(cat session_id.txt)" "https://envoy.lan/production.json" | jq
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Test changes thoroughly with your Envoy system
4. Submit a pull request with clear description

## License

Licensed under the Apache License, Version 2.0. See the driver file header for full license terms.

## Acknowledgments

- Enphase Energy for the Envoy system
- Hubitat Elevation community
- OAuth 2.0 / PKCE specification authors

---

**Note**: This project is not officially affiliated with Enphase Energy. Use at your own risk and ensure compliance with Enphase terms of service.