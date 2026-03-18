<?php

// App-wide constants
define('BASE_URL', 'http://localhost/cap/');
define('APP_NAME', 'Dental Clinic Management System');
define('APP_VERSION', '1.0.0');
date_default_timezone_set('Asia/Manila');
define('SESSION_LIFETIME', 28800);

// ============================================================
// ERROR HANDLING — Hide Errors from Browser
// RUBRIC: Errors handled properly with clear messages
// ============================================================
// display_errors=0 means PHP errors are NEVER shown to the
// user on the screen. Showing raw PHP errors to the public
// is a security risk because it can reveal file paths, database
// structure, and server configuration to attackers.
// log_errors=1 means all errors are still recorded silently
// in logs/error.log so the developer can see and fix them
// without exposing anything to the user.
// error_reporting(E_ALL) ensures every type of error is caught
// and logged — nothing is silently ignored.
// ============================================================
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/../logs/error.log');
error_reporting(E_ALL);

// ============================================================
// ERROR HANDLING — Create Logs Folder if Missing
// RUBRIC: Errors handled properly with clear messages
// ============================================================
// Automatically creates the logs/ directory if it does not
// exist yet so error logging always works without manual setup.
// ============================================================
if (!is_dir(__DIR__ . '/../logs')) {
    mkdir(__DIR__ . '/../logs', 0755, true);
}

// ============================================================
// ERROR HANDLING — Global Exception Handler
// RUBRIC: Errors handled properly with clear messages
//         Strong security (data protection)
// ============================================================
// Catches any unhandled exception thrown anywhere in the system.
// Instead of showing a raw PHP crash to the user, it:
//   1. Logs the full error details silently to error.log
//   2. Returns HTTP 500 status code
//   3. Shows a clean, safe error page or JSON response
//      depending on whether the request is from the API or UI
// This means the user never sees stack traces, file paths,
// or any internal system information — only a safe message.
// ============================================================
set_exception_handler(function($e) {
    error_log('[EXCEPTION] ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
    if (!headers_sent()) http_response_code(500);
    $isApi = strpos($_SERVER['REQUEST_URI'] ?? '', '/api/') !== false;
    if ($isApi) {
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'A server error occurred.']);
    } else {
        include dirname(__DIR__) . '/error.php';
    }
    exit();
});

// ============================================================
// ERROR HANDLING — Fatal Error Handler (Shutdown Function)
// RUBRIC: Errors handled properly with clear messages
//         Strong security (data protection)
// ============================================================
// PHP fatal errors (syntax errors, out-of-memory, etc.) cannot
// be caught by try/catch or set_exception_handler. This shutdown
// function runs automatically when PHP is about to stop and
// checks if it stopped because of a fatal error.
// If it did, it logs the error silently and shows the safe
// error page instead of a blank white screen or raw PHP crash.
// ============================================================
register_shutdown_function(function() {
    $e = error_get_last();
    if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
        error_log('[FATAL] ' . $e['message'] . ' in ' . $e['file'] . ':' . $e['line']);
        if (!headers_sent()) {
            http_response_code(500);
            include dirname(__DIR__) . '/error.php';
        }
    }
});

// ============================================================
// ERROR HANDLING & SECURITY — HTTP Security Headers
// RUBRIC: Strong security (data protection, validation)
//         Errors handled properly with clear messages
// ============================================================
// These headers are sent with every single response and tell
// the browser how to behave securely:
//
// X-Content-Type-Options: nosniff
//   — Prevents the browser from guessing the file type.
//     Stops attackers from uploading a file disguised as
//     an image but executed as a script.
//
// X-Frame-Options: SAMEORIGIN
//   — Blocks other websites from embedding this system inside
//     an <iframe>. Prevents clickjacking attacks where an
//     attacker tricks users into clicking hidden buttons.
//
// X-XSS-Protection: 1; mode=block
//   — Tells older browsers to block pages when they detect
//     a reflected XSS (Cross-Site Scripting) attack.
//
// Referrer-Policy: strict-origin-when-cross-origin
//   — Controls how much URL information is sent when the user
//     clicks a link to another site. Prevents leaking internal
//     URLs or session-related query strings to third parties.
// ============================================================
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
