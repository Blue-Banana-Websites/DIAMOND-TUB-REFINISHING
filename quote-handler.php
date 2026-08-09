<?php

/**
 * Photo quote form handler.
 *
 * Receives the hero "Show Us What Needs Refinishing" form (3 photos +
 * name/phone/email/notes), validates everything server-side, emails the
 * photos and details to the business, and emails the sender a confirmation.
 */

declare(strict_types=1);

use PHPMailer\PHPMailer\PHPMailer;

if (!is_dir(__DIR__ . '/data')) {
    @mkdir(__DIR__ . '/data', 0700, true);
}

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/data/quote-handler-error.log');

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

const MAX_PHOTO_BYTES = 20 * 1024 * 1024; // 20MB per photo
const REQUIRED_PHOTO_COUNT = 3;
const MIN_SECONDS_BEFORE_SUBMIT = 3; // basic bot heuristic
const RATE_LIMIT_SECONDS = 30; // per IP, between submissions

/**
 * Always respond as JSON and stop.
 */
function respond(int $httpStatus, bool $success, string $message): void
{
    http_response_code($httpStatus);
    echo json_encode(['success' => $success, 'message' => $message]);
    exit;
}

function client_ip(): string
{
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

/**
 * Very small file-based per-IP throttle. Not a substitute for a real
 * WAF/captcha, but enough to blunt naive scripted abuse on a low-traffic
 * small-business site.
 *
 * Only successful submissions count against the limit (see
 * record_submission()) — a visitor fixing a typo and resubmitting right
 * away should never get falsely blocked.
 */
function is_rate_limited(string $ip): bool
{
    $data = read_rate_limit_data();
    $key = hash('sha256', $ip);
    $now = time();

    return isset($data[$key]) && ($now - $data[$key]) < RATE_LIMIT_SECONDS;
}

function record_submission(string $ip): void
{
    $dir = __DIR__ . '/data';
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    $file = $dir . '/ratelimit.json';

    $handle = @fopen($file, 'c+');
    if ($handle === false) {
        return;
    }

    if (flock($handle, LOCK_EX)) {
        $contents = stream_get_contents($handle);
        $data = $contents ? json_decode($contents, true) : [];
        if (!is_array($data)) {
            $data = [];
        }

        $now = time();

        // Prune old entries so the file doesn't grow forever.
        foreach ($data as $k => $ts) {
            if (!is_int($ts) || ($now - $ts) > 3600) {
                unset($data[$k]);
            }
        }

        $data[hash('sha256', $ip)] = $now;
        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode($data));
        fflush($handle);

        flock($handle, LOCK_UN);
    }
    fclose($handle);
}

function read_rate_limit_data(): array
{
    $file = __DIR__ . '/data/ratelimit.json';
    if (!is_file($file)) {
        return [];
    }

    $contents = @file_get_contents($file);
    if ($contents === false) {
        return [];
    }

    $data = json_decode($contents, true);

    return is_array($data) ? $data : [];
}

/**
 * Identify an uploaded image's real format by inspecting its bytes
 * (not the client-supplied filename or Content-Type, both of which are
 * trivially spoofable). Returns 'jpeg' | 'png' | 'webp' | 'heic' | null.
 */
function detect_image_format(string $tmpPath): ?string
{
    if (function_exists('finfo_open')) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        if ($finfo !== false) {
            $mime = finfo_file($finfo, $tmpPath);
            finfo_close($finfo);

            switch ($mime) {
                case 'image/jpeg':
                    return 'jpeg';
                case 'image/png':
                    return 'png';
                case 'image/webp':
                    return 'webp';
                case 'image/heic':
                case 'image/heif':
                case 'image/heic-sequence':
                case 'image/heif-sequence':
                    return 'heic';
            }
        }
    }

    // Fallback: read the file's magic bytes directly. This matters most
    // for HEIC/HEIF — many shared-hosting libmagic databases are too old
    // to recognize it and report a generic type instead.
    $head = @file_get_contents($tmpPath, false, null, 0, 32);
    if ($head === false || strlen($head) < 12) {
        return null;
    }

    // JPEG: FF D8 FF
    if (substr($head, 0, 3) === "\xFF\xD8\xFF") {
        return 'jpeg';
    }

    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if (substr($head, 0, 8) === "\x89PNG\x0D\x0A\x1A\x0A") {
        return 'png';
    }

    // WebP: 'RIFF' .... 'WEBP'
    if (substr($head, 0, 4) === 'RIFF' && substr($head, 8, 4) === 'WEBP') {
        return 'webp';
    }

    // HEIC/HEIF: ISOBMFF container — bytes 4-7 are 'ftyp', bytes 8-11 are
    // a brand identifying it as HEIC/HEIF (vs. e.g. an MP4/MOV).
    if (substr($head, 4, 4) === 'ftyp') {
        $brand = substr($head, 8, 4);
        $heicBrands = ['heic', 'heix', 'heim', 'heis', 'hevc', 'hevx', 'hevm', 'hevs', 'mif1', 'msf1'];
        if (in_array($brand, $heicBrands, true)) {
            return 'heic';
        }
    }

    return null;
}

function sanitize_filename(string $name, string $extension): string
{
    $name = pathinfo($name, PATHINFO_FILENAME);
    $name = preg_replace('/[^A-Za-z0-9_-]+/', '-', $name) ?? '';
    $name = trim($name, '-');
    $name = mb_substr($name, 0, 60);
    if ($name === '') {
        $name = 'photo';
    }

    return $name . '.' . $extension;
}

/**
 * For the multi-line notes field: keeps newlines, strips other control chars.
 */
function clean_text(string $value, int $maxLength): string
{
    $value = trim($value);
    $value = str_replace(["\r\n", "\r"], "\n", $value);
    $value = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', '', $value) ?? '';

    return mb_substr($value, 0, $maxLength);
}

/**
 * For single-line fields (name, phone, email): strips ALL control chars,
 * including newlines, so a crafted value can never break out into a new
 * email header/body line.
 */
function clean_line(string $value, int $maxLength): string
{
    $value = trim($value);
    $value = preg_replace('/[\x00-\x1F]/', '', $value) ?? '';

    return mb_substr($value, 0, $maxLength);
}

// ---------------------------------------------------------------------
// Request checks
// ---------------------------------------------------------------------

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    respond(405, false, 'Method not allowed.');
}

$configPath = __DIR__ . '/config.php';
if (!is_file($configPath)) {
    error_log('quote-handler: missing config.php');
    respond(500, false, 'The quote form is not configured yet. Please call or email us directly.');
}
$config = require $configPath;

$ip = client_ip();
if (is_rate_limited($ip)) {
    respond(429, false, 'Please wait a moment before submitting another request.');
}

// PHP silently empties $_POST/$_FILES if the request exceeded
// post_max_size — detect that case and give a clear message instead of a
// confusing generic "required field" error.
$contentLength = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
if (empty($_POST) && empty($_FILES) && $contentLength > 0) {
    respond(413, false, 'Your photos were too large to upload. Please try smaller images or email them to contact@diamondtubrefinishing.ca.');
}

// Honeypot: real visitors never see or fill this field (hidden via CSS).
// Bots that fill every field will trip it.
$honeypot = trim((string) ($_POST['website'] ?? ''));

// Basic bot-speed heuristic: the form records when step 1 was shown; a
// submission faster than a human could plausibly fill the form out is
// treated the same as a honeypot hit.
$startedAt = (int) ($_POST['ts'] ?? 0);
$tooFast = $startedAt > 0 && (time() - intdiv($startedAt, 1000)) < MIN_SECONDS_BEFORE_SUBMIT;

if ($honeypot !== '' || $tooFast) {
    // Pretend success so scripted spam doesn't learn to adapt.
    error_log(sprintf('quote-handler: spam heuristic tripped (ip=%s honeypot=%s tooFast=%s)', $ip, $honeypot !== '' ? 'yes' : 'no', $tooFast ? 'yes' : 'no'));
    respond(200, true, 'Thanks! Your quote request has been received.');
}

// ---------------------------------------------------------------------
// Field validation
// ---------------------------------------------------------------------

$errors = [];

$name = clean_line((string) ($_POST['name'] ?? ''), 120);
if ($name === '') {
    $errors[] = 'Please enter your name.';
}

$phone = clean_line((string) ($_POST['phone'] ?? ''), 30);
if ($phone === '' || !preg_match('/^[0-9 ()+.\-]{7,30}$/', $phone)) {
    $errors[] = 'Please enter a valid phone number.';
}

$email = clean_line((string) ($_POST['email'] ?? ''), 254);
if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'Please enter a valid email address.';
}

$notes = clean_text((string) ($_POST['notes'] ?? ''), 3000);

// ---------------------------------------------------------------------
// Photo validation
// ---------------------------------------------------------------------

$photoFiles = $_FILES['photos'] ?? null;
$photos = []; // [['tmp' => ..., 'filename' => ..., 'format' => ...], ...]

if (
    !is_array($photoFiles)
    || !isset($photoFiles['error']) || !is_array($photoFiles['error'])
    || count($photoFiles['error']) !== REQUIRED_PHOTO_COUNT
) {
    $errors[] = 'Please attach exactly 3 photos.';
} else {
    foreach ($photoFiles['error'] as $i => $err) {
        if ($err === UPLOAD_ERR_NO_FILE) {
            $errors[] = 'Please attach all 3 photos.';
            continue;
        }
        if ($err !== UPLOAD_ERR_OK) {
            $errors[] = 'One of your photos failed to upload. Please try again.';
            continue;
        }

        $tmpPath = $photoFiles['tmp_name'][$i];
        $size = (int) $photoFiles['size'][$i];

        if (!is_uploaded_file($tmpPath)) {
            $errors[] = 'One of your photos failed to upload. Please try again.';
            continue;
        }
        if ($size <= 0 || $size > MAX_PHOTO_BYTES) {
            $errors[] = 'Each photo must be under 20MB.';
            continue;
        }

        $format = detect_image_format($tmpPath);
        if ($format === null) {
            $errors[] = 'Photos must be JPEG, PNG, WebP, or HEIC/HEIF images.';
            continue;
        }

        $extension = $format === 'jpeg' ? 'jpg' : $format;
        $photos[] = [
            'tmp' => $tmpPath,
            'filename' => sanitize_filename((string) $photoFiles['name'][$i], $extension),
            'format' => $format,
        ];
    }

    if (count($photos) !== REQUIRED_PHOTO_COUNT && count($errors) === 0) {
        $errors[] = 'Please attach exactly 3 valid photos.';
    }
}

if (!empty($errors)) {
    respond(400, false, implode(' ', array_unique($errors)));
}

// ---------------------------------------------------------------------
// Send emails
// ---------------------------------------------------------------------

require __DIR__ . '/vendor/phpmailer/src/Exception.php';
require __DIR__ . '/vendor/phpmailer/src/PHPMailer.php';
require __DIR__ . '/vendor/phpmailer/src/SMTP.php';

function configure_smtp(PHPMailer $mail, array $config): void
{
    $mail->isSMTP();
    $mail->Host = $config['smtp_host'];
    $mail->Port = $config['smtp_port'];
    $mail->SMTPAuth = true;
    $mail->Username = $config['smtp_username'];
    $mail->Password = $config['smtp_password'];
    $mail->SMTPSecure = $config['smtp_secure'];
    $mail->CharSet = 'UTF-8';
}

$submittedAt = date('Y-m-d H:i:s');

try {
    // --- Email #1: notify the business, with photos attached ---
    $businessMail = new PHPMailer(true);
    configure_smtp($businessMail, $config);
    $businessMail->setFrom($config['from_email'], $config['from_name']);
    $businessMail->addAddress($config['business_to'], $config['business_name']);
    $businessMail->addReplyTo($email, $name);
    $businessMail->isHTML(false);
    $businessMail->Subject = 'New Photo Quote Request — ' . $name;
    $businessMail->Body = implode("\n", [
        "New photo quote request from the website.",
        "",
        "Name:  {$name}",
        "Phone: {$phone}",
        "Email: {$email}",
        "Submitted: {$submittedAt}",
        "",
        "Message:",
        $notes !== '' ? $notes : '(none)',
        "",
        '3 photos attached.',
    ]);

    foreach ($photos as $photo) {
        $businessMail->addAttachment($photo['tmp'], $photo['filename']);
    }

    $businessMail->send();
    record_submission($ip);
} catch (\Throwable $e) {
    error_log('quote-handler: failed to send business notification — ' . $e->getMessage());
    respond(502, false, 'Sorry, something went wrong sending your request. Please call us at (403) 510-7859 or email contact@diamondtubrefinishing.ca directly.');
}

try {
    // --- Email #2: confirm receipt to the customer ---
    $customerMail = new PHPMailer(true);
    configure_smtp($customerMail, $config);
    $customerMail->setFrom($config['from_email'], $config['business_name']);
    $customerMail->addAddress($email, $name);
    $customerMail->isHTML(false);
    $customerMail->Subject = 'We received your photo quote request';
    $customerMail->Body = implode("\n", [
        "Hi {$name},",
        "",
        "Thanks for requesting a quote from Diamond Tub Refinishing! We've " .
            "received your photos and details, and our team is preparing " .
            "your quote now. We'll be in touch shortly — usually the same day.",
        "",
        "If anything comes up in the meantime, you can reach us at:",
        "(403) 510-7859",
        "contact@diamondtubrefinishing.ca",
        "",
        "Talk soon,",
        "Diamond Tub Refinishing",
    ]);

    $customerMail->send();
} catch (\Throwable $e) {
    // The quote itself made it to the business — don't fail the whole
    // request just because the courtesy confirmation didn't send.
    error_log('quote-handler: failed to send customer confirmation — ' . $e->getMessage());
}

respond(200, true, "Thanks, {$name}! Your quote request has been received and is being prepared.");
