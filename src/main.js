import init, { WasmSigner } from "@jveko/zsign-wasm";
import { unzipSync, zipSync } from "fflate";
import plist from "plist";

const $=s=>document.querySelector(s);
const p12=$('#p12'),prov=$('#prov'),ipa=$('#ipa'),password=$('#password');
const signBtn=$('#sign'),logEl=$('#log'),bar=$('#bar'),dl=$('#download');
let engineReady=false,provBytes=null,p12Bytes=null,ipaFile=null;
function log(t){logEl.textContent=t} function progress(n){bar.style.width=n+'%'}
async function boot(){try{await init();engineReady=true;$('#engineStatus').textContent='المحرك جاهز • محليًا';refresh()}catch(e){$('#engineStatus').textContent='تعذر تحميل محرك WASM';log('تعذر تحميل محرك التوقيع. تأكد من npm install ثم npm run build.')}}
function refresh(){signBtn.disabled=!(engineReady&&p12Bytes&&provBytes&&ipaFile)}
p12.onchange=async()=>{p12Bytes=p12.files[0]?new Uint8Array(await p12.files[0].arrayBuffer()):null;$('#p12name').textContent=p12.files[0]?.name||'لم يتم اختيار ملف';refresh()}
prov.onchange=async()=>{if(!prov.files[0])return;provBytes=new Uint8Array(await prov.files[0].arrayBuffer());$('#provname').textContent=prov.files[0].name;$('#provMeta').textContent='تم تحميل الملف محليًا. سيقوم المحرك باستخراج بيانات الاعتماد أثناء التوقيع.';refresh()}
ipa.onchange=()=>{ipaFile=ipa.files[0]||null;$('#ipaname').textContent=ipaFile?.name||'لم يتم اختيار ملف';refresh()}
function findApp(files){const keys=Object.keys(files).filter(x=>/^Payload\/[^/]+\.app\//.test(x));const apps=[...new Set(keys.map(x=>x.split('/').slice(0,2).join('/')))];if(!apps.length)throw new Error('لم يتم العثور على Payload/*.app داخل IPA.');return apps[0]}
function findExecutable(files,app){const plistPath=app+'/Info.plist';const info=plist.parse(new TextDecoder().decode(files[plistPath]));if(!info.CFBundleExecutable)throw new Error('تعذر تحديد CFBundleExecutable.');return{info,plistPath,execPath:app+'/'+info.CFBundleExecutable}}
signBtn.onclick=async()=>{try{dl.classList.add('hidden');progress(5);log('جاري قراءة IPA محليًا…');const files=unzipSync(new Uint8Array(await ipaFile.arrayBuffer()));const app=findApp(files);const{info,plistPath,execPath}=findExecutable(files,app);const bundleId=$('#bundleId').value.trim()||info.CFBundleIdentifier;if(!bundleId)throw new Error('Bundle ID غير موجود.');progress(18);log('جاري تجهيز الشهادة والـProvision…');const signer=new WasmSigner(p12Bytes,password.value,provBytes);signer.set_main_executable(info.CFBundleExecutable);const prefix=app+'/';const resourceNames=Object.keys(files).filter(k=>k.startsWith(prefix)&&!k.includes('/_CodeSignature/'));let done=0;for(const path of resourceNames){if(path===execPath||path===plistPath||path.endsWith('/embedded.mobileprovision'))continue;const rel=path.slice(prefix.length);if(!rel)continue;signer.hash_file(rel,files[path]);done++;if(done%20===0)progress(18+Math.min(55,done/resourceNames.length*55))}const codeResources=signer.build_code_resources();files[execPath]=signer.sign_macho_fat(files[execPath],bundleId,files[plistPath],codeResources);for(const k of Object.keys(files))if(k.startsWith(app+'/_CodeSignature/'))delete files[k];progress(88);log('جاري إنشاء IPA الموقعة…');const out=zipSync(files,{level:6});const url=URL.createObjectURL(new Blob([out],{type:'application/octet-stream'}));const name=($('#outputName').value.trim()||'signed.ipa').replace(/\.ipa$/i,'')+'.ipa';dl.href=url;dl.download=name;dl.textContent='تنزيل '+name;dl.classList.remove('hidden');progress(100);log('اكتمل التوقيع محليًا. لم تُرفع الملفات إلى خادم.')}catch(e){console.error(e);progress(0);log('فشل التوقيع: '+(e?.message||e))}}
boot();
