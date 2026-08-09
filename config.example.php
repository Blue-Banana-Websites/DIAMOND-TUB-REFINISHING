<?php

/**
 * Copy this file to config.php on the server and fill in real values.
 * config.php is listed in .gitignore and must never be committed —
 * it holds the SMTP mailbox password.
 */

return [
    // SMTP credentials for the contact@diamondtubrefinishing.ca mailbox.
    // Get these from the hosting control panel (cPanel > Email Accounts >
    // Connect Devices, or similar).
    'smtp_host' => 'mail.diamondtubrefinishing.ca',
    'smtp_port' => 465,               // 465 = implicit TLS, 587 = STARTTLS
    'smtp_secure' => 'ssl',           // 'ssl' for port 465, 'tls' for port 587
    'smtp_username' => 'contact@diamondtubrefinishing.ca',
    'smtp_password' => 'REPLACE_WITH_REAL_MAILBOX_PASSWORD',

    // Where quote requests and photos are delivered.
    'business_to' => 'contact@diamondtubrefinishing.ca',
    'business_name' => 'Diamond Tub Refinishing',

    // Must be a mailbox on the same domain as smtp_username, or most SMTP
    // servers will reject the send.
    'from_email' => 'contact@diamondtubrefinishing.ca',
    'from_name' => 'Diamond Tub Refinishing Website',
];
