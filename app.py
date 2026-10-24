from flask import Flask, request, send_from_directory, jsonify, render_template_string, abort
from werkzeug.utils import secure_filename
from pathlib import Path
import secrets
import os

APP_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = APP_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
MAX_FILE_MB = int(os.environ.get("CHILLYFILE_MAX_MB", "512"))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_MB * 1024 * 1024

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ChillyFile.io — Simple file sharing</title>
<style>
:root{color-scheme:dark;--bg:#081426;--panel:#0e2038;--blue:#20a8ff;--text:#f4f8ff;--muted:#b8cbe5}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 50% 20%,#122b49 0%,var(--bg) 65%);font-family:Inter,Segoe UI,Arial,sans-serif;color:var(--text);min-height:100vh}
header{height:82px;border-bottom:1px solid #203650;display:flex;align-items:center;justify-content:space-between;padding:0 clamp(18px,4vw,56px)}
.brand{font-weight:800;font-size:clamp(22px,3vw,34px);letter-spacing:-1px;color:var(--text)}.brand span{color:var(--blue)}
nav{color:var(--muted);font-size:15px}main{max-width:900px;margin:58px auto 50px;padding:0 20px;text-align:center}h1{font-size:clamp(36px,5vw,56px);margin:0 0 10px;letter-spacing:-1.5px} .sub{font-size:21px;color:#b8d5f7;margin-bottom:32px}
.drop{border:2px dashed #169fff;border-radius:16px;background:#0c1e34b8;padding:48px 18px;cursor:pointer;transition:.18s;min-height:260px;display:flex;flex-direction:column;align-items:center;justify-content:center}
.drop.drag{background:#123454;border-color:#8bd5ff;transform:scale(1.01)}.cloud{font-size:54px;color:var(--blue);line-height:1.2}.drop strong{font-size:22px;margin:14px 0 8px}.drop p{margin:0;color:var(--muted)}.tiny{font-size:14px;margin-top:20px!important}
.status{display:none;text-align:left;margin-top:18px;background:#092f38;border:1px solid #12616a;border-radius:12px;padding:16px;color:#d9fff6;overflow-wrap:anywhere}.status a{color:#7ed0ff}.bar{height:7px;background:#18334d;border-radius:10px;overflow:hidden;margin-top:12px}.bar i{display:block;height:100%;width:0;background:linear-gradient(90deg,#168cff,#51e0d0);transition:width .15s}
.features{display:grid;grid-template-columns:repeat(4,1fr);gap:22px;margin:60px auto 0;text-align:center}.feature .ico{font-size:32px;color:var(--blue)}.feature b{display:block;margin:10px 0;font-size:17px}.feature p{color:var(--muted);font-size:14px;line-height:1.5;margin:0}
footer{color:#7890ad;text-align:center;font-size:12px;padding:20px}
@media(max-width:650px){header{height:70px}nav{display:none}main{margin-top:38px}.drop{padding:35px 14px;min-height:230px}.features{grid-template-columns:repeat(2,1fr);margin-top:42px}}
</style></head>
<body>
<header><div class="brand">Chilly<span>File.io</span></div><nav>Simple uploads · Shareable links · No ads</nav></header>
<main><h1>Upload Files</h1><div class="sub">Fast. Simple. No weird ads.</div>
<div class="drop" id="drop" role="button" tabindex="0" aria-label="Choose files to upload">
<div class="cloud">☁↑</div><strong>Drag &amp; drop files here</strong><p>or click to browse</p><p class="tiny">Files start uploading automatically after selection</p>
<input id="files" type="file" multiple hidden>
</div>
<div class="status" id="status" aria-live="polite"><div id="message">Preparing upload…</div><div class="bar"><i id="progress"></i></div><div id="links"></div></div>
</main>
<script>
const drop=document.getElementById('drop'), picker=document.getElementById('files'), statusBox=document.getElementById('status');
drop.addEventListener('click',()=>picker.click()); drop.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();picker.click()}});
picker.addEventListener('change',()=>uploadFiles([...picker.files]));
for(const ev of ['dragenter','dragover']) drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.add('drag')});
for(const ev of ['dragleave','drop']) drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.remove('drag')});
drop.addEventListener('drop',e=>uploadFiles([...e.dataTransfer.files]));
async function uploadFiles(files){
 if(!files.length)return; statusBox.style.display='block';document.getElementById('links').innerHTML='';
 for(const file of files){
  document.getElementById('message').textContent=`Uploading ${file.name}…`;document.getElementById('progress').style.width='0%';
  try{
   const form=new FormData();form.append('file',file);
   const result=await new Promise((resolve,reject)=>{
    const xhr=new XMLHttpRequest();xhr.open('POST','/upload');xhr.upload.onprogress=e=>{if(e.lengthComputable)document.getElementById('progress').style.width=Math.round(e.loaded/e.total*100)+'%'};
    xhr.onload=()=>{let data;try{data=JSON.parse(xhr.responseText)}catch{reject(new Error('Unexpected server response'));return} if(xhr.status>=200&&xhr.status<300)resolve(data);else reject(new Error(data.error||'Upload failed'))};
    xhr.onerror=()=>reject(new Error('Network error'));xhr.send(form);
   });
   document.getElementById('message').textContent=`Uploaded: ${file.name}`;
   const row=document.createElement('p');row.innerHTML='Share link: ';const a=document.createElement('a');a.href=result.url;a.textContent=result.url;a.target='_blank';a.rel='noopener';row.appendChild(a);
   const copy=document.createElement('button');copy.textContent=' Copy link';copy.style.cssText='margin-left:8px;cursor:pointer';copy.onclick=async()=>{try{await navigator.clipboard.writeText(result.url);copy.textContent=' Copied!'}catch{prompt('Copy this link:',result.url)}};row.appendChild(copy);document.getElementById('links').appendChild(row);
  }catch(err){document.getElementById('message').textContent=`Could not upload ${file.name}: ${err.message}`;}
 }
 picker.value='';
}
</script></body></html>"""

@app.get("/")
def index():
    return render_template_string(PAGE)

@app.post("/upload")
def upload():
    file = request.files.get("file")
    if not file or not file.filename:
        return jsonify(error="No file selected"), 400
    original = secure_filename(file.filename) or "file"
    token = secrets.token_urlsafe(9)
    stored_name = f"{token}__{original}"
    try:
        file.save(UPLOAD_DIR / stored_name)
    except Exception:
        return jsonify(error="Could not save this file"), 500
    return jsonify(url=request.host_url.rstrip("/") + "/f/" + token, name=original)

@app.get("/f/<token>")
def download(token):
    matches = list(UPLOAD_DIR.glob(token + "__*"))

    if not matches:
        abort(404)

    path = matches[0]
    filename = path.name.split("__", 1)[1]

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Download - ChillyFile</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {
                background: #081426;
                color: white;
                font-family: Arial, sans-serif;
                text-align: center;
                padding: 100px 20px;
            }
            .box {
                background: #0e2038;
                padding: 40px;
                border-radius: 16px;
                max-width: 450px;
                margin: auto;
            }
            h1 { color: #20a8ff; }
            .button {
                display: inline-block;
                background: #168cff;
                color: white;
                padding: 15px 35px;
                border-radius: 8px;
                text-decoration: none;
                font-weight: bold;
                margin-top: 20px;
            }
            .filename {
                overflow-wrap: anywhere;
                color: #b8cbe5;
            }
        </style>
    </head>
    <body>
        <div class="box">
            <h1>ChillyFile</h1>
            <h2>Your file is ready!</h2>
            <p class="filename">{{ filename }}</p>
            <a class="button" href="{{ url_for('get_file', token=token) }}">
                Download File
            </a>
        </div>
    </body>
    </html>
    """, filename=filename, token=token)


@app.get("/download/<token>")
def get_file(token):
    matches = list(UPLOAD_DIR.glob(token + "__*"))

    if not matches:
        abort(404)

    path = matches[0]

    return send_from_directory(
        UPLOAD_DIR,
        path.name,
        as_attachment=True,
        download_name=path.name.split("__", 1)[1]
    )
 
    # Token is the random prefix; filenames are never accepted directly from the URL.
    matches = list(UPLOAD_DIR.glob(token + "__*"))
    if not matches:
        abort(404)
    path = matches[0]
    return send_from_directory(UPLOAD_DIR, path.name, as_attachment=True, download_name=path.name.split("__",1)[1])

@app.errorhandler(413)
def too_large(_):
    return jsonify(error=f"File is too large. Server limit is {MAX_FILE_MB} MB."), 413

if __name__ == "__main__":
    print("ChillyFile is starting at http://127.0.0.1:5000")
    print("For local testing only. Read README before exposing it to the internet.")
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT","5000")), debug=False)
 
