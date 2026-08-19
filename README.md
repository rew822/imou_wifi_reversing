# IMOU Cue 2 Wi-Fi Configuration Tool

Configure an IMOU Cue 2 camera's Wi-Fi connection without using the IMOU Life app.

This proof-of-concept Python tool was created by reverse engineering the camera's legacy Wi-Fi provisioning protocol. It connects directly to the camera, retrieves its RSA public key, encrypts the supplied Wi-Fi credentials, and sends the configuration over the Dahua DHIP protocol.

> [!WARNING]
> This is an unofficial reverse-engineering project and is not affiliated with or supported by IMOU or Dahua. It has been developed for the IMOU Cue 2 and may not work with other models or firmware versions. Use it only with devices and networks you own or are authorized to manage.

## Requirements

- Python 3
- The [`cryptography`](https://pypi.org/project/cryptography/) Python package
- Network access to the camera on TCP port `37777`
- The camera's current IP address
- The SSID, password, and encryption value of the destination Wi-Fi network

## Quick start

Clone the repository and create an isolated Python environment:

```bash
git clone https://github.com/rew822/imou_wifi_reversing.git
cd imou_wifi_reversing
python3 -m venv .venv
.venv/bin/pip install cryptography
```

Make sure your computer can reach the camera  by connecting to the cameras own Access Point (the password is in the QR code on the back SC:<Password>), then configure its Wi-Fi connection:

```bash
.venv/bin/python imou_wifi_config.py \
  --ip 192.168.0.108 \
  --ssid "iot" \
  --password "<WIFI Password>" \
  --encryption 9
```

A successful configuration ends with:

```text
[+] Status 0x78 - SUCCESS
```

The camera may change IP address after it joins the destination Wi-Fi network. Check your router's DHCP leases if it is no longer available at its previous address.

## Command-line options

| Option | Required | Description |
| --- | --- | --- |
| `--ip` | Yes | Current IP address of the camera |
| `--ssid` | Yes* | Destination Wi-Fi network name; maximum of 35 UTF-8 bytes |
| `--password` | Yes* | Destination Wi-Fi password; maximum of 127 UTF-8 bytes |
| `--encryption` | Yes* | Scan-derived combined Wi-Fi encryption value |
| `--test-rsa` | No | Test connectivity and RSA public-key retrieval without changing Wi-Fi settings |
| `-h`, `--help` | No | Display command help |

`*` The SSID, password, and encryption value are required unless `--test-rsa` is used.

The example above uses the encryption value `9`. This field is a protocol-specific, scan-derived value rather than a general label such as `WPA2`. Other access point configurations may require a different value.

## Test camera connectivity

To verify that the camera is reachable and responds with an RSA public key without sending Wi-Fi credentials:

```bash
.venv/bin/python imou_wifi_config.py \
  --ip 192.168.0.108 \
  --test-rsa
```

## How it works

The configuration flow uses one TCP connection to the camera on port `37777`:

1. Request the camera's 2048-bit RSA public key with the legacy `config` command.
2. Build the 200-byte legacy Wi-Fi configuration structure.
3. Generate a random 128-bit AES key and encrypt the Wi-Fi structure using AES-128 in ECB mode with zero padding.
4. Encrypt the AES key with the camera's RSA key using PKCS#1 v1.5 padding.
5. Send the hybrid-encrypted payload using the `C1/83` configuration request.
6. Treat camera status code `0x78` as successful acceptance.

The password is masked in terminal output. Credentials are sent to the camera in encrypted form, but passing a password on the command line may expose it locally through shell history or process listings.

## Troubleshooting

### Connection refused or timed out

- Confirm that the IP address belongs to the camera and is pingable
- Check if connected to the cameras own Access Point (the password is in the QR code on the back SC:<Password>), if there is no Access Point reset the camera
- Make sure the computer and camera can reach each other on the local network.
- Check that a firewall is not blocking TCP port `37777`.
- Run the `--test-rsa` command before attempting configuration.

### `cryptography module not available`

Install the dependency inside the virtual environment:

```bash
.venv/bin/pip install cryptography
```

### No RSA key in response

The camera or its firmware may not support the protocol implemented here. Confirm the address and try `--test-rsa` again while the camera is in the same provisioning state used for setup.

### No response after sending the configuration

The tool cannot confirm acceptance when the camera does not return a response. The camera may also disconnect while switching networks. Check whether it appears in the destination router's DHCP client list before retrying.

## Project status

This is an experimental proof of concept based on reverse engineering an IMOU Cue 2 camera. Protocol details and encryption values may vary across camera models, hardware revisions, and firmware releases. Contributions with verified captures or results from other devices are welcome.
