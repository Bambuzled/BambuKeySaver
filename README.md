# BambuKeySaver

Every time Bambu Studio starts, if the network plugin is installed it will generate a request to `https://api.bambulab.com/v1/iot-service/api/user/applications/...`. The server will validate the request and return a JSON response with a certificate list, CRL, and key. These three pieces of information are required to communicate with Bambu printers that are not in Developer mode. Enabling full 3rd-party interoperability with these printers requires obtaining these three items. Each set is unique to the network plugins on each OS/platform.

The returned key is encrypted using a customized AES cipher with a static key. Thanks to https://github.com/danielwoz/BambuSlicerKeySaver for identifying and publishing the details of that custom cipher, which is the crux of getting that key. This repo is really just distilling what that repo is doing (most of it is unnecessary, but the underlying reversing effort is a real gem) into the simplest possible set of steps I could manage to obtain those three pieces of information.

Generating valid `https://api.bambulab.com/v1/iot-service/api/user/applications/...` requests is difficult, but capturing the ones sent by Bambu Studio on startup is currently pretty easy. The Capture scripts here automate that and save both the request URL (`trigger-url.txt`) and response (`trigger-response.json`). Once captured, the same request URL can be re-used indefinitely (just paste it into your web browser, then copy the Raw Data and save it to a text file) to obtain fresh responses from the server without needing to re-capture a new request.

Once a response JSON file has been obtained, the `bambu-api-decrypt.py` script will parse it to decrypt the key and generate PEM files for the key, certs, and CRL. These can be used with 3rd-party software that support them to enable full interoperability with Bambu printers. See for example https://github.com/ClusterM/open-bamboo-networking#option-b-cloud-mode-without-developer-mode (no affiliation).

The certificate associated with the key currently lasts 1.5 years. When it expires, or if Bambu ever revokes the key using the CRL, you will need to get a fresh response with updated cert+key+CRL. 

## Windows

[Install Wireshark](https://www.wireshark.org/#download). Accept all the defaults. 

[Install Bambu Studio](https://bambulab.com/en-us/download/studio) in the default location. Start it and go through the initial setup (including downloading the network plugin), but you do NOT need to login or connect to any printers. Then exit.

[Install Python](https://www.python.org/downloads/). If you have any PowerShell windows open, close and re-open them after the install completes.

Open PowerShell and navigate to the folder where the Capture-BambuCert.ps1 script is saved.

Ensure Bambu Studio is not already running, then run the capture script.
```powershell
powershell -ep bypass ./Capture-BambuCert.ps1
```

If everything worked it will print a list of files it generated. One of these should end in `trigger-response.json`. 

Run the python decryptor against that JSON file.
```powershell
python .\bambu-api-decrypt.py .\<your-trigger-response.json>
```

## Linux

Ensure Wireshark and Python are installed via your package manager. Typically `sudo apt install wireshark python3`. 

Download the Bambu Studio AppImage from one of the GitHub releases: https://github.com/bambulab/BambuStudio/releases/latest

Make it executable (`chmod +x ./Bambu...AppImage`). Start it and go through the initial setup (including downloading the network plugin), but you don't need to login or connect to any printers. Then exit. Sometimes it's janky and you need to run it more than once to get it to go through all the initial setup stuff. 

Run the capture script, pointing it to the downloaded AppImage.
```bash
./capture-bambu-cert.sh /path/to/Bambu...AppImage
```

If everything worked it will print a list of files it generated. One of these should end in `trigger-response.json`. 

Run the python decryptor against that JSON file.
```powershell
python3 ./bambu-api-decrypt.py ./<your-trigger-response.json>
```

## MacOS

No implemented. But the Linux bash script can probably be modified pretty easily to do so. 

## Compatible Versions

Tested with v2.8.2.61 of Bambu Studio, and the latest network plugin versions at the time:
- https://public-cdn.bblmw.com/upgrade/studio/plugins/02.08.02.60/72163aeb05/win_02.08.02.60.zip
- https://public-cdn.bblmw.com/upgrade/studio/plugins/02.08.02.54/f1a94b8828/linux_02.08.02.54.zip

In the future Bambu may modify Studio and/or the plugins to prevent this repo from working. In that case, you have two main options while waiting to see if I update this repo:
- Manually download and install the Studio and plugin versions listed above (or any earlier ones) and run the scripts against them.
- Use a previously-saved request URL to get a fresh response directly. Based on how Bambu built this entire process, I anticipate these will necessarily remain valid and usable into the far future.

