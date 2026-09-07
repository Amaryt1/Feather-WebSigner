<?php
// Feather WebSigner - real multipart upload endpoint.
// Store uploaded files server-side, but deny direct public access via .htaccess.
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok'=>false,'error'=>'POST فقط'], JSON_UNESCAPED_UNICODE);
    exit;
}

$max = 350 * 1024 * 1024; // 350 MB
if (empty($_FILES['file'])) {
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>'لم يتم إرسال ملف'], JSON_UNESCAPED_UNICODE);
    exit;
}

$f = $_FILES['file'];
if ($f['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>'فشل رفع الملف: '.$f['error']], JSON_UNESCAPED_UNICODE);
    exit;
}
if ($f['size'] <= 0 || $f['size'] > $max) {
    http_response_code(413);
    echo json_encode(['ok'=>false,'error'=>'حجم الملف غير مسموح (الحد 350 MB)'], JSON_UNESCAPED_UNICODE);
    exit;
}

$type = isset($_POST['type']) ? (string)$_POST['type'] : 'file';
$allowed = ['p12'=>['p12','pfx'], 'provision'=>['mobileprovision'], 'ipa'=>['ipa']];
if (!isset($allowed[$type])) {
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>'نوع الملف غير مسموح'], JSON_UNESCAPED_UNICODE);
    exit;
}

$name = basename((string)$f['name']);
$ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
if (!in_array($ext, $allowed[$type], true)) {
    http_response_code(415);
    echo json_encode(['ok'=>false,'error'=>'امتداد الملف لا يطابق نوعه'], JSON_UNESCAPED_UNICODE);
    exit;
}

$storage = __DIR__ . DIRECTORY_SEPARATOR . 'storage';
if (!is_dir($storage) && !mkdir($storage, 0700, true)) {
    http_response_code(500);
    echo json_encode(['ok'=>false,'error'=>'تعذر إنشاء مساحة التخزين'], JSON_UNESCAPED_UNICODE);
    exit;
}

$id = bin2hex(random_bytes(16));
$target = $storage . DIRECTORY_SEPARATOR . $id . '.' . $ext;
if (!move_uploaded_file($f['tmp_name'], $target)) {
    http_response_code(500);
    echo json_encode(['ok'=>false,'error'=>'تعذر حفظ الملف على الخادم'], JSON_UNESCAPED_UNICODE);
    exit;
}
@chmod($target, 0600);

// لا نعيد رابطًا عامًا للملف؛ نعيد معرفًا فقط.
echo json_encode([
    'ok'=>true,
    'id'=>$id,
    'type'=>$type,
    'name'=>$name,
    'size'=>(int)$f['size']
], JSON_UNESCAPED_UNICODE);
