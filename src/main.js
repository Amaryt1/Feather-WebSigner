import initWasm, { WasmSigner } from "@jveko/zsign-wasm";
import wasmUrl from "@jveko/zsign-wasm/zsign_wasm_bg.wasm?url";
import { unzipSync, zipSync } from "fflate";

const $ = (s) => document.querySelector(s);
const p12Input = $("#p12");
const provInput = $("#prov");
const ipaInput = $("#ipa");
const passwordInput = $("#password");
const signButton = $("#sign");
const logEl = $("#log");
const bar = $("#bar");
const download = $("#download");
const engineStatus = $("#engineStatus");

let p12Bytes = null;
let provBytes = null;
let ipaFile = null;
let ipaInfo = null;
let wasmReady = false;
let wasmPromise = null;
let outputUrl = null;

function size(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}

function progress(value) {
  if (bar) bar.style.width = `${Math.max(0, Math.min(100, value))}%`;
}

function log(message, kind = "info") {
  if (!logEl) return;
  const icon = kind === "ok" ? "✓" : kind === "error" ? "✕" : "•";
  logEl.textContent = `${icon} ${message}`;
}

function clearDownload() {
  if (outputUrl) URL.revokeObjectURL(outputUrl);
  outputUrl = null;
  download?.classList.add("hidden");
  download?.removeAttribute("href");
}

function setLabel(selector, file) {
  const el = $(selector);
  if (el) el.textContent = file ? `${file.name} • ${size(file.size)}` : "لم يتم اختيار ملف";
}

function refreshButton() {
  const ready = wasmReady && !!p12Bytes && !!provBytes && !!ipaFile && !!passwordInput?.value;
  if (signButton) signButton.disabled = !ready;
}

async function ensureWasm() {
  if (wasmReady) return;
  if (wasmPromise) return wasmPromise;
  wasmPromise = (async () => {
    engineStatus.textContent = "جاري تحميل محرك التوقيع…";
    try {
      const response = await fetch(wasmUrl, { cache: "force-cache" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const bytes = await response.arrayBuffer();
      await initWasm({ module_or_path: bytes });
      wasmReady = true;
      engineStatus.textContent = "المحرك جاهز • التوقيع محليًا";
      engineStatus.dataset.state = "ready";
      log("تم تحميل محرك WASM بنجاح.", "ok");
      refreshButton();
    } catch (error) {
      wasmPromise = null;
      engineStatus.textContent = "تعذر تحميل محرك التوقيع";
      engineStatus.dataset.state = "error";
      log(`خطأ في WASM: ${error?.message || error}`, "error");
      throw error;
    }
  })();
  return wasmPromise;
}

function bytesOf(file) {
  return file.arrayBuffer().then((buffer) => new Uint8Array(buffer));
}

function isMachO(data) {
  if (!data || data.length < 4) return false;
  const magic = ((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]) >>> 0;
  return [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca].includes(magic);
}

function findApp(files) {
  const plistPath = Object.keys(files).find((p) => /^Payload\/[^/]+\.app\/Info\.plist$/.test(p));
  if (!plistPath) throw new Error("لم يتم العثور على Payload/*.app/Info.plist داخل IPA.");
  return plistPath.slice(0, -"Info.plist".length);
}

function parseInfo(data) {
  const info = WasmSigner.parse_info_plist(data);
  if (!info) throw new Error("تعذر قراءة Info.plist.");
  return info;
}

function extensionPrefixes(files, appPrefix) {
  const result = new Set();
  const root = `${appPrefix}PlugIns/`;
  for (const path of Object.keys(files)) {
    if (!path.startsWith(root)) continue;
    const rest = path.slice(root.length);
    const first = rest.split("/")[0];
    if (first.endsWith(".appex")) result.add(`${root}${first}/`);
  }
  return [...result];
}

async function inspectIPA(file) {
  await ensureWasm();
  const files = unzipSync(await bytesOf(file));
  const appPrefix = findApp(files);
  const plistPath = `${appPrefix}Info.plist`;
  const plistData = files[plistPath];
  const info = parseInfo(plistData);
  const bundleId = info.bundle_id || info.CFBundleIdentifier || "";
  const executable = info.executable || info.CFBundleExecutable || "";
  if (!bundleId) throw new Error("لم يتم العثور على Bundle ID.");
  if (!executable) throw new Error("لم يتم العثور على اسم الملف التنفيذي.");
  const execPath = `${appPrefix}${executable}`;
  if (!files[execPath] || !isMachO(files[execPath])) {
    throw new Error(`الملف التنفيذي غير صالح أو غير موجود: ${executable}`);
  }
  const extensions = extensionPrefixes(files, appPrefix);
  ipaInfo = { files, appPrefix, plistPath, plistData, info, bundleId, executable, execPath, extensions };
  $("#bundleId").value = bundleId;
  if (extensions.length) {
    log(`تم اكتشاف ${extensions.length} App Extension. يجب توفير Provisioning مطابق لكل Extension؛ لن يتم إنشاء IPA غير صالحة.`, "error");
  } else {
    log(`تم فحص IPA بنجاح • ${bundleId} • ${size(file.size)}`, "ok");
  }
  refreshButton();
}

async function handleP12(file) {
  try {
    p12Bytes = await bytesOf(file);
    setLabel("#p12name", file);
    clearDownload();
    log("تم اختيار P12 وحفظه في ذاكرة المتصفح فقط؛ لم يتم رفعه إلى الخادم.", "ok");
  } catch (error) {
    p12Bytes = null;
    log(`تعذر قراءة P12: ${error?.message || error}`, "error");
  }
  refreshButton();
}

async function handleProvision(file) {
  try {
    provBytes = await bytesOf(file);
    setLabel("#provname", file);
    $("#provMeta").textContent = `تم تحميل ${file.name} • ${size(file.size)} • محلي فقط`;
    clearDownload();
    log("تم اختيار MobileProvision وحفظه في ذاكرة المتصفح فقط.", "ok");
  } catch (error) {
    provBytes = null;
    log(`تعذر قراءة MobileProvision: ${error?.message || error}`, "error");
  }
  refreshButton();
}

async function handleIPA(file) {
  ipaFile = file;
  setLabel("#ipaname", file);
  clearDownload();
  progress(0);
  try {
    await inspectIPA(file);
  } catch (error) {
    ipaInfo = null;
    log(`فشل فحص IPA: ${error?.message || error}`, "error");
  }
  refreshButton();
}

function enableDrop(label, handler) {
  if (!label) return;
  ["dragenter", "dragover"].forEach((name) => label.addEventListener(name, (event) => {
    event.preventDefault();
    label.classList.add("dragging");
  }));
  ["dragleave", "drop"].forEach((name) => label.addEventListener(name, (event) => {
    event.preventDefault();
    label.classList.remove("dragging");
  }));
  label.addEventListener("drop", async (event) => {
    const file = event.dataTransfer?.files?.[0];
    if (file) await handler(file);
  });
}

p12Input?.addEventListener("change", () => {
  const file = p12Input.files?.[0];
  if (file) handleP12(file);
});
provInput?.addEventListener("change", () => {
  const file = provInput.files?.[0];
  if (file) handleProvision(file);
});
ipaInput?.addEventListener("change", () => {
  const file = ipaInput.files?.[0];
  if (file) handleIPA(file);
});
passwordInput?.addEventListener("input", refreshButton);
$("#bundleId")?.addEventListener("input", refreshButton);

enableDrop(p12Input?.closest(".drop"), handleP12);
enableDrop(provInput?.closest(".drop"), handleProvision);
enableDrop(ipaInput?.closest(".drop"), handleIPA);

signButton?.addEventListener("click", async () => {
  signButton.disabled = true;
  clearDownload();
  progress(2);
  try {
    await ensureWasm();
    if (!p12Bytes || !provBytes || !ipaFile) throw new Error("اختر P12 وMobileProvision وIPA أولًا.");
    if (!passwordInput.value) throw new Error("أدخل كلمة مرور P12.");
    if (!ipaInfo) await inspectIPA(ipaFile);

    const { files, appPrefix, plistData, executable, execPath, extensions } = ipaInfo;
    if (extensions.length) throw new Error("IPA تحتوي App Extensions. هذه النسخة تمنع إنتاج IPA غير صالحة؛ استخدم Provisioning مستقلًا لكل Extension.");

    log("جاري التحقق من الشهادة وملف Provisioning…");
    const signer = new WasmSigner(p12Bytes, passwordInput.value, provBytes);
    const teamId = signer.team_id();
    if (!teamId) throw new Error("تعذر استخراج Team ID. تحقق من P12 وProvisioning وكلمة المرور.");
    log(`بيانات التوقيع صالحة • Team ID: ${teamId}`, "ok");
    progress(12);

    const bundleId = $("#bundleId").value.trim() || ipaInfo.bundleId;
    const output = { ...files };

    for (const path of Object.keys(output)) {
      if (path.startsWith(`${appPrefix}_CodeSignature/`)) delete output[path];
    }
    output[`${appPrefix}embedded.mobileprovision`] = provBytes;
    signer.set_main_executable(executable);

    const nested = [];
    for (const [path, data] of Object.entries(files)) {
      if (!path.startsWith(appPrefix) || path === execPath) continue;
      if (path.startsWith(`${appPrefix}_CodeSignature/`)) continue;
      if (path.endsWith("/Info.plist") || path.endsWith("/embedded.mobileprovision")) continue;
      if (isMachO(data)) nested.push(path);
    }

    if (nested.length) {
      log(`جاري توقيع ${nested.length} ملفًا داخليًا…`);
      for (let i = 0; i < nested.length; i++) {
        const path = nested[i];
        const leaf = path.split("/").pop();
        const identifier = leaf.replace(/\.dylib$/i, "");
        try {
          output[path] = signer.sign_macho_fat(files[path], identifier, null, null);
        } catch (error) {
          throw new Error(`فشل توقيع ${path}: ${error?.message || error}`);
        }
        progress(15 + ((i + 1) / nested.length) * 30);
      }
    }

    log("جاري حساب CodeResources من الملفات النهائية…");
    const resources = Object.keys(output).filter((path) => {
      if (!path.startsWith(appPrefix)) return false;
      if (path === execPath) return false;
      if (path.startsWith(`${appPrefix}_CodeSignature/`)) return false;
      return true;
    });
    for (let i = 0; i < resources.length; i++) {
      const path = resources[i];
      signer.hash_file(path.slice(appPrefix.length), output[path]);
      if (i % 20 === 0) progress(45 + (i / Math.max(resources.length, 1)) * 18);
    }

    const codeResources = signer.build_code_resources();
    output[`${appPrefix}_CodeSignature/CodeResources`] = codeResources;
    progress(68);

    log("جاري توقيع الملف التنفيذي الرئيسي…");
    output[execPath] = signer.sign_macho_fat(output[execPath], bundleId, plistData, codeResources);
    progress(82);

    log("جاري إنشاء IPA النهائية…");
    const archive = zipSync(output, { level: 6 });
    outputUrl = URL.createObjectURL(new Blob([archive], { type: "application/octet-stream" }));
    const baseName = ($( "#outputName")?.value.trim() || `${ipaFile.name.replace(/\.ipa$/i, "")}-signed`).replace(/\.ipa$/i, "");
    download.href = outputUrl;
    download.download = `${baseName}.ipa`;
    download.textContent = `تنزيل ${baseName}.ipa • ${size(archive.length)}`;
    download.classList.remove("hidden");
    progress(100);
    log("اكتمل التوقيع بنجاح. لم يتم رفع P12 أو Provisioning أو IPA إلى خادم.", "ok");
  } catch (error) {
    console.error(error);
    progress(0);
    log(`فشل التوقيع: ${error?.message || error}`, "error");
  } finally {
    refreshButton();
  }
});

ensureWasm().catch(() => refreshButton());