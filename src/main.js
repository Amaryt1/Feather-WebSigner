import initWasm, { WasmSigner } from "@jveko/zsign-wasm";
import wasmUrl from "@jveko/zsign-wasm/zsign_wasm_bg.wasm?url";
import { unzipSync, zipSync } from "fflate";

const $ = (s) => document.querySelector(s);
const p12Input = $("#p12"), provInput = $("#prov"), ipaInput = $("#ipa");
const passwordInput = $("#password"), signButton = $("#sign"), logEl = $("#log");
const bar = $("#bar"), download = $("#download"), engineStatus = $("#engineStatus");
let p12Bytes = null, provBytes = null, ipaFile = null, ipaInfo = null;
let wasmReady = false, wasmPromise = null, outputUrl = null;

const size = (n) => n < 1024 ? `${n} B` : n < 1048576 ? `${(n/1024).toFixed(1)} KB` : `${(n/1048576).toFixed(1)} MB`;
const progress = (n) => { if (bar) bar.style.width = `${Math.max(0, Math.min(100,n))}%`; };
function log(message, kind="info") { if (logEl) logEl.textContent = `${kind === "ok" ? "✓" : kind === "error" ? "✕" : "•"} ${message}`; }
function clearDownload() { if (outputUrl) URL.revokeObjectURL(outputUrl); outputUrl=null; download?.classList.add("hidden"); download?.removeAttribute("href"); }
function setLabel(id,file) { const el=$(id); if(el) el.textContent=file ? `${file.name} • ${size(file.size)}` : "لم يتم اختيار ملف"; }
function refreshButton() { if(signButton) signButton.disabled=!(wasmReady && p12Bytes && provBytes && ipaFile && ipaInfo && passwordInput?.value); }

async function ensureWasm() {
  if(wasmReady) return true;
  if(wasmPromise) return wasmPromise;
  wasmPromise=(async()=>{
    try {
      if(engineStatus) engineStatus.textContent="جاري تحميل محرك التوقيع…";
      const response=await fetch(`${wasmUrl}?v=202609071`,{cache:"no-store"});
      if(!response.ok) throw new Error(`HTTP ${response.status}`);
      const bytes=await response.arrayBuffer();
      await initWasm({module_or_path:bytes});
      wasmReady=true;
      if(engineStatus){engineStatus.textContent="المحرك جاهز • التوقيع محليًا";engineStatus.dataset.state="ready";}
      log("تم تحميل محرك WASM بنجاح.","ok"); refreshButton(); return true;
    } catch(e) {
      wasmReady=false; wasmPromise=null;
      if(engineStatus){engineStatus.textContent="تعذر تحميل محرك التوقيع";engineStatus.dataset.state="error";}
      log(`خطأ في محرك التوقيع: ${e?.message||e}`,"error"); throw e;
    }
  })();
  return wasmPromise;
}
const readFile=async(f)=>new Uint8Array(await f.arrayBuffer());
function isMachO(d){ if(!d||d.length<4)return false; const m=((d[0]<<24)|(d[1]<<16)|(d[2]<<8)|d[3])>>>0; return [0xfeedface,0xfeedfacf,0xcefaedfe,0xcffaedfe,0xcafebabe,0xbebafeca].includes(m); }
function findApp(files){const p=Object.keys(files).find(x=>/^Payload\/[^/]+\.app\/Info\.plist$/.test(x));if(!p)throw Error("لم يتم العثور على تطبيق صالح داخل IPA.");return p.slice(0,-10);}
function parseInfo(data){const x=WasmSigner.parse_info_plist(data);if(!x)throw Error("تعذر قراءة Info.plist.");return x;}
function extensions(files,prefix){const out=new Set(),root=`${prefix}PlugIns/`;for(const p of Object.keys(files)){if(p.startsWith(root)){const n=p.slice(root.length).split("/")[0];if(n.endsWith(".appex"))out.add(`${root}${n}/`);}}return [...out];}

async function inspectIPA(file){
  await ensureWasm(); const files=unzipSync(await readFile(file)); const prefix=findApp(files);
  const plistPath=`${prefix}Info.plist`, plistData=files[plistPath], info=parseInfo(plistData);
  const bundleId=info.bundle_id||info.CFBundleIdentifier||"", executable=info.executable||info.CFBundleExecutable||"";
  if(!bundleId||!executable)throw Error("تعذر استخراج بيانات التطبيق من Info.plist.");
  const execPath=`${prefix}${executable}`; if(!files[execPath]||!isMachO(files[execPath]))throw Error("الملف التنفيذي داخل IPA غير صالح.");
  const ext=extensions(files,prefix); ipaInfo={files,appPrefix:prefix,plistData,bundleId,executable,execPath,extensions:ext};
  const b=$("#bundleId");if(b){b.value=bundleId;b.readOnly=true;}
  log(ext.length?`تم اكتشاف ${ext.length} App Extension؛ يلزم Provisioning مطابق.`:`تم فحص IPA بنجاح • ${bundleId}` ,ext.length?"error":"ok"); refreshButton();
}
async function handleP12(f){if(!f)return;try{p12Bytes=await readFile(f);setLabel("#p12name",f);clearDownload();log(`تم اختيار ${f.name} • ${size(f.size)} • محلي فقط.` ,"ok");}catch(e){p12Bytes=null;log(`تعذر قراءة P12: ${e?.message||e}`,"error");}refreshButton();}
async function handleProv(f){if(!f)return;try{provBytes=await readFile(f);setLabel("#provname",f);const m=$("#provMeta");if(m)m.textContent=`تم تحميل ${f.name} • ${size(f.size)} • محلي فقط`;clearDownload();log(`تم اختيار ${f.name} • ${size(f.size)} • محلي فقط.` ,"ok");}catch(e){provBytes=null;log(`تعذر قراءة MobileProvision: ${e?.message||e}`,"error");}refreshButton();}
async function handleIPA(f){if(!f)return;ipaFile=f;setLabel("#ipaname",f);clearDownload();progress(0);log(`تم اختيار ${f.name} • جاري الفحص…`);try{await inspectIPA(f);}catch(e){ipaInfo=null;log(`فشل فحص IPA: ${e?.message||e}`,"error");}refreshButton();}
function bind(input,handler){input?.addEventListener("change",e=>{const f=e.target.files?.[0];if(f)handler(f);});}
bind(p12Input,handleP12);bind(provInput,handleProv);bind(ipaInput,handleIPA);passwordInput?.addEventListener("input",refreshButton);

signButton?.addEventListener("click",async()=>{
  signButton.disabled=true;clearDownload();progress(2);
  try{
    await ensureWasm(); if(!p12Bytes||!provBytes||!ipaFile)throw Error("اختر P12 وMobileProvision وIPA أولًا."); if(!passwordInput.value)throw Error("أدخل كلمة مرور P12."); if(!ipaInfo)await inspectIPA(ipaFile);
    const {files,appPrefix,plistData,executable,execPath,extensions:ext}=ipaInfo; if(ext.length)throw Error("IPA تحتوي App Extensions وتحتاج Provisioning مستقلًا.");
    log("جاري التحقق من الشهادة وProvisioning…"); const signer=new WasmSigner(p12Bytes,passwordInput.value,provBytes); const team=signer.team_id(); if(!team)throw Error("تعذر استخراج Team ID."); progress(12);
    const output={...files}; for(const p of Object.keys(output))if(p.startsWith(`${appPrefix}_CodeSignature/`))delete output[p];
    output[`${appPrefix}embedded.mobileprovision`]=provBytes; signer.set_main_executable(executable);
    const nested=[]; for(const [p,d] of Object.entries(files)){if(!p.startsWith(appPrefix)||p===execPath||p.startsWith(`${appPrefix}_CodeSignature/`)||p.endsWith("/Info.plist")||p.endsWith("/embedded.mobileprovision"))continue;if(isMachO(d))nested.push(p);}
    for(let i=0;i<nested.length;i++){const p=nested[i],leaf=p.split("/").pop(),id=leaf.replace(/\.dylib$/i,"");output[p]=signer.sign_macho_fat(files[p],id,null,null);progress(15+(i+1)/Math.max(1,nested.length)*30);}
    const resources=Object.keys(output).filter(p=>p.startsWith(appPrefix)&&p!==execPath&&!p.startsWith(`${appPrefix}_CodeSignature/`));
    for(let i=0;i<resources.length;i++)signer.hash_file(resources[i].slice(appPrefix.length),output[resources[i]]);
    const cr=signer.build_code_resources();output[`${appPrefix}_CodeSignature/CodeResources`]=cr;progress(68);
    log(`جاري توقيع التطبيق • Team ID: ${team}`);output[execPath]=signer.sign_macho_fat(output[execPath],ipaInfo.bundleId,plistData,cr);progress(82);
    const archive=zipSync(output,{level:6});outputUrl=URL.createObjectURL(new Blob([archive],{type:"application/octet-stream"}));
    const name=(($("#outputName")?.value.trim())||"signed.ipa").replace(/\.ipa$/i,"");download.href=outputUrl;download.download=`${name}.ipa`;download.textContent=`تنزيل ${name}.ipa • ${size(archive.length)}`;download.classList.remove("hidden");progress(100);log("اكتمل التوقيع محليًا بنجاح.","ok");
  }catch(e){console.error(e);progress(0);log(`فشل التوقيع: ${e?.message||e}`,"error");}finally{refreshButton();}
});
ensureWasm().catch(()=>refreshButton());
