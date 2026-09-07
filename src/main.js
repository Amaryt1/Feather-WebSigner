import initWasm, { WasmSigner } from "@jveko/zsign-wasm";
import wasmUrl from "@jveko/zsign-wasm/zsign_wasm_bg.wasm?url";
import { unzipSync, zipSync } from "fflate";

const $ = (selector) => document.querySelector(selector);

const p12Input = $("#p12");
const profileInput = $("#prov");
const ipaInput = $("#ipa");
const passwordInput = $("#password");
const signButton = $("#sign");
const logElement = $("#log");
const progressBar = $("#bar");
const downloadLink = $("#download");
const engineStatus = $("#engineStatus");

let wasmReady = false;
let wasmInitPromise = null;
let p12Bytes = null;
let profileBytes = null;
let ipaFile = null;
let outputUrl = null;
let ipaInfo = null;

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function setProgress(value) {
  progressBar.style.width = `${Math.max(0, Math.min(100, value))}%`;
}

function log(message, type = "info") {
  const prefix = type === "ok" ? "✓" : type === "error" ? "✕" : "•";
  logElement.textContent = `${prefix} ${message}`;
}

function clearDownload() {
  if (outputUrl) {
    URL.revokeObjectURL(outputUrl);
    outputUrl = null;
  }
  downloadLink.classList.add("hidden");
  downloadLink.removeAttribute("href");
}

function updateReadiness() {
  const ready = wasmReady && p12Bytes && profileBytes && ipaFile && passwordInput.value.length > 0;
  signButton.disabled = !ready;
  signButton.title = ready
    ? "ابدأ توقيع IPA محليًا"
    : "اختر P12 وMobileProvision وIPA وأدخل كلمة مرور P12 بعد تحميل المحرك";
}

async function initWasm() {
  if (wasmReady) return;
  if (wasmInitPromise) return wasmInitPromise;

  wasmInitPromise = (async () => {
    engineStatus.textContent = "جاري تحميل محرك التوقيع…";
    try {
      const response = await fetch(wasmUrl, { cache: "force-cache" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const wasmBytes = await response.arrayBuffer();
      await initWasm({ module_or_path: wasmBytes });
      wasmReady = true;
      engineStatus.textContent = "المحرك جاهز • التوقيع محليًا";
      engineStatus.dataset.state = "ready";
      updateReadiness();
      log("محرك WASM جاهز للعمل.", "ok");
    } catch (error) {
      wasmInitPromise = null;
      engineStatus.textContent = "تعذر تحميل محرك التوقيع";
      engineStatus.dataset.state = "error";
      log(`تعذر تحميل WASM: ${error?.message || error}`, "error");
      throw error;
    }
  })();

  return wasmInitPromise;
}

function readAsBytes(file) {
  return file.arrayBuffer().then((buffer) => new Uint8Array(buffer));
}

function setFileLabel(id, file) {
  const element = $(id);
  if (!element) return;
  element.textContent = file ? `${file.name} • ${formatSize(file.size)}` : "لم يتم اختيار ملف";
}

function isMachO(data) {
  if (!data || data.length < 4) return false;
  const magic = ((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]) >>> 0;
  return [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca].includes(magic);
}

function parseInfoPlist(data) {
  if (!wasmReady) throw new Error("محرك WASM غير جاهز لقراءة Info.plist.");
  const info = WasmSigner.parse_info_plist(data);
  if (!info) throw new Error("تعذر قراءة Info.plist.");
  return info;
}

function findMainApp(files) {
  const paths = Object.keys(files);
  const appPath = paths.find((path) => /^Payload\/[^/]+\.app\/Info\.plist$/.test(path));
  if (!appPath) throw new Error("لم يتم العثور على Payload/*.app/Info.plist داخل IPA.");
  return appPath.slice(0, appPath.lastIndexOf("Info.plist"));
}

function findNestedAppExtensions(files, appPrefix) {
  const prefixes = new Set();
  const marker = `${appPrefix}PlugIns/`;
  for (const path of Object.keys(files)) {
    if (!path.startsWith(marker)) continue;
    const match = path.match(new RegExp(`^${escapeRegExp(marker)}([^/]+\\.appex)/`));
    if (match) prefixes.add(`${marker}${match[1]}/`);
  }
  return [...prefixes];
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function inspectIpa(file) {
  await initWasm();
  const files = unzipSync(await readAsBytes(file));
  const appPrefix = findMainApp(files);
  const plistPath = `${appPrefix}Info.plist`;
  const infoPlist = files[plistPath];
  if (!infoPlist) throw new Error("Info.plist غير موجود.");

  const info = parseInfoPlist(infoPlist);
  const bundleId = info.bundle_id || info.CFBundleIdentifier || "";
  const executable = info.executable || info.CFBundleExecutable || "";
  if (!bundleId) throw new Error("تعذر استخراج Bundle ID من Info.plist.");
  if (!executable) throw new Error("تعذر استخراج اسم الملف التنفيذي من Info.plist.");

  const execPath = `${appPrefix}${executable}`;
  if (!files[execPath] || !isMachO(files[execPath])) {
    throw new Error(`الملف التنفيذي الرئيسي غير موجود أو ليس Mach-O: ${executable}`);
  }

  const nestedApps = findNestedAppExtensions(files, appPrefix);
  ipaInfo = { files, appPrefix, plistPath, infoPlist, info, bundleId, executable, execPath, nestedApps };
  $("#bundleId").value = bundleId;

  if (nestedApps.length) {
    log(`تم اكتشاف ${nestedApps.length} App Extension. يلزم Provisioning مستقل لكل Extension؛ لن يتم إنشاء IPA غير صالحة.`, "error");
  } else {
    log(`تم فحص IPA: ${bundleId} • ${formatSize(file.size)}`, "ok");
  }
  updateReadiness();
}

async function handleP12(file) {
  p12Bytes = await readAsBytes(file);
  setFileLabel("#p12name", file);
  clearDownload();
  log("تم تحميل P12 إلى ذاكرة المتصفح فقط؛ لم يتم رفعه إلى الموقع.", "ok");
  updateReadiness();
}

async function handleProfile(file) {
  profileBytes = await readAsBytes(file);
  setFileLabel("#provname", file);
  clearDownload();
  try {
    await initWasm();
    const signer = new WasmSigner(p12Bytes || new Uint8Array(), passwordInput.value || "", profileBytes);
    const team = signer.team_id();
    $("#provMeta").textContent = team ? `تم تحميل الملف محليًا • Team ID: ${team}` : "تم تحميل الملف محليًا.";
  } catch (_) {
    $("#provMeta").textContent = "تم تحميل الملف محليًا. سيتم التحقق منه عند بدء التوقيع.";
  }
  log("تم تحميل MobileProvision إلى ذاكرة المتصفح فقط.", "ok");
  updateReadiness();
}

async function handleIpa(file) {
  if (!file) return;
  ipaFile = file;
  setFileLabel("#ipaname", file);
  clearDownload();
  setProgress(0);
  try {
    await inspectIpa(file);
  } catch (error) {
    ipaInfo = null;
    log(`فحص IPA فشل: ${error?.message || error}`, "error");
  }
  updateReadiness();
}

function attachDrop(labelSelector, input, handler) {
  const label = input.closest(labelSelector);
  if (!label) return;
  ["dragenter", "dragover"].forEach((eventName) => {
    label.addEventListener(eventName, (event) => {
      event.preventDefault();
      label.classList.add("dragging");
    });
  });
  ["dragleave", "drop"].forEach((eventName) => {
    label.addEventListener(eventName, (event) => {
      event.preventDefault();
      label.classList.remove("dragging");
    });
  });
  label.addEventListener("drop", async (event) => {
    const file = event.dataTransfer?.files?.[0];
    if (file) await handler(file);
  });
}

p12Input.addEventListener("change", async () => {
  const file = p12Input.files?.[0];
  if (file) await handleP12(file);
});

profileInput.addEventListener("change", async () => {
  const file = profileInput.files?.[0];
  if (file) await handleProfile(file);
});

ipaInput.addEventListener("change", async () => {
  const file = ipaInput.files?.[0];
  if (file) await handleIpa(file);
});

passwordInput.addEventListener("input", updateReadiness);
$("#bundleId").addEventListener("input", updateReadiness);

attachDrop(".drop", p12Input, handleP12);
attachDrop(".drop", profileInput, handleProfile);
attachDrop(".drop", ipaInput, handleIpa);

signButton.addEventListener("click", async () => {
  signButton.disabled = true;
  clearDownload();
  setProgress(3);

  try {
    await initWasm();
    if (!p12Bytes || !profileBytes || !ipaFile) throw new Error("اختر P12 وMobileProvision وIPA أولًا.");
    if (!passwordInput.value) throw new Error("أدخل كلمة مرور ملف P12.");

    log("جاري إنشاء محرك التوقيع والتحقق من الشهادة…");
    const signer = new WasmSigner(p12Bytes, passwordInput.value, profileBytes);
    const teamId = signer.team_id();
    if (!teamId) throw new Error("تعذر استخراج Team ID من الشهادة/Provisioning.");
    log(`تم التحقق من بيانات التوقيع • Team ID: ${teamId}`, "ok");
    setProgress(12);

    if (!ipaInfo) await inspectIpa(ipaFile);
    const { files, appPrefix, plistPath, infoPlist, info, executable, execPath, nestedApps } = ipaInfo;
    if (nestedApps.length) {
      throw new Error("هذه IPA تحتوي App Extensions. يجب توقيع كل Extension بملف Provisioning مطابق له قبل إنشاء IPA صالحة.");
    }

    const requestedBundleId = $("#bundleId").value.trim() || ipaInfo.bundleId;
    if (!requestedBundleId) throw new Error("Bundle ID غير موجود.");

    const outputFiles = { ...files };
    for (const path of Object.keys(outputFiles)) {
      if (path.startsWith(`${appPrefix}_CodeSignature/`)) delete outputFiles[path];
    }

    // Use the selected provisioning profile inside the resulting app.
    outputFiles[`${appPrefix}embedded.mobileprovision`] = profileBytes;
    signer.set_main_executable(executable);

    // Sign nested Mach-O frameworks/dylibs first. The main executable is signed last.
    const nestedMachO = [];
    for (const [path, data] of Object.entries(files)) {
      if (!path.startsWith(appPrefix) || path === execPath || path.startsWith(`${appPrefix}_CodeSignature/`)) continue;
      if (path.endsWith("/embedded.mobileprovision") || path.endsWith("/Info.plist")) continue;
      if (isMachO(data)) nestedMachO.push(path);
    }

    setProgress(20);
    if (nestedMachO.length) {
      log(`جاري توقيع ${nestedMachO.length} ملف Framework/Dylib…`);
      for (let index = 0; index < nestedMachO.length; index++) {
        const path = nestedMachO[index];
        const data = files[path];
        const leaf = path.split("/").pop();
        const identifier = leaf.replace(/\.dylib$/i, "");
        try {
          outputFiles[path] = signer.sign_macho_fat(data, identifier, null, null);
        } catch (error) {
          throw new Error(`فشل توقيع ${path}: ${error?.message || error}`);
        }
        setProgress(20 + ((index + 1) / nestedMachO.length) * 25);
      }
    }

    // Hash the exact final resource bytes, including the selected profile.
    log("جاري بناء CodeResources…");
    let hashed = 0;
    const totalResourceFiles = Object.keys(outputFiles).filter((path) =>
      path.startsWith(appPrefix) &&
      !path.startsWith(`${appPrefix}_CodeSignature/`) &&
      path !== execPath &&
    ).length;

    for (const [path, data] of Object.entries(outputFiles)) {
      if (!path.startsWith(appPrefix)) continue;
      const relative = path.slice(appPrefix.length);
      if (!relative || relative.startsWith("_CodeSignature/")) continue;
      if (path === execPath) continue;
      signer.hash_file(relative, data);
      hashed++;
      if (hashed % 25 === 0) setProgress(45 + Math.min(25, (hashed / Math.max(totalResourceFiles, 1)) * 25));
    }

    const codeResources = signer.build_code_resources();
    outputFiles[`${appPrefix}_CodeSignature/CodeResources`] = codeResources;
    setProgress(73);

    // Sign the main executable using the final Info.plist and CodeResources.
    log("جاري توقيع الملف التنفيذي الرئيسي…");
    outputFiles[execPath] = signer.sign_macho_fat(
      files[execPath],
      requestedBundleId,
      infoPlist,
      codeResources,
    );
    setProgress(86);

    const ipaBytes = zipSync(outputFiles, { level: 6 });
    const blob = new Blob([ipaBytes], { type: "application/octet-stream" });
    outputUrl = URL.createObjectURL(blob);

    const requestedName = $("#outputName").value.trim() || "signed.ipa";
    const outputName = requestedName.replace(/\.ipa$/i, "") + ".ipa";
    downloadLink.href = outputUrl;
    downloadLink.download = outputName;
    downloadLink.textContent = `تنزيل ${outputName} • ${formatSize(ipaBytes.length)}`;
    downloadLink.classList.remove("hidden");

    setProgress(100);
    log("اكتمل التوقيع محليًا بنجاح. لم يتم رفع P12 أو Provisioning أو IPA إلى أي خادم.", "ok");
  } catch (error) {
    console.error(error);
    setProgress(0);
    log(`فشل التوقيع: ${error?.message || error}`, "error");
  } finally {
    updateReadiness();
  }
});

window.addEventListener("beforeunload", () => {
  if (outputUrl) URL.revokeObjectURL(outputUrl);
});

initWasm().catch(() => {});
updateReadiness();
