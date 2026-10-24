# ChillyFile.io — starter project

A clean, ad-free file-sharing website starter with automatic upload, drag-and-drop, and shareable download links.

## Run on Windows

1. Install Python 3.10+ from https://www.python.org/downloads/ (check “Add Python to PATH”).
2. Extract this ZIP.
3. Open the extracted `chillyfile` folder in File Explorer.
4. Click the address bar, type `cmd`, and press Enter.
5. Run:

   ```
   py -m pip install -r requirements.txt
   py app.py
   ```

6. Open http://127.0.0.1:5000 in your browser.
7. Pick or drag in a file. It uploads automatically and displays a share link.

## Important

This is a **working local prototype**, not a production public hosting service. It stores files in the `uploads` folder on the computer running the app. A link will only work for other people if the server is deployed on a publicly reachable host and configured correctly.

Before public deployment, add authentication or abuse controls, rate limits, file expiration/deletion, storage quotas, malware scanning, HTTPS, logging/privacy notices, and a production server. Do not expose the development server directly to the internet. Uploaded files may be accessible to anyone who has the link. The default upload limit is 512 MB; set `CHILLYFILE_MAX_MB` to change it.
