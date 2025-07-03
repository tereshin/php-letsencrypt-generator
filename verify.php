<?php
// verify.php – Проверка валидности SSL сертификата

require __DIR__ . '/vendor/autoload.php';

// Функция для проверки сертификата
function verifyCertificate($certPath, $keyPath, $chainPath = null) {
    $results = [];
    
    // Проверяем существование файлов
    if (!file_exists($certPath)) {
        $results['error'] = 'Файл сертификата не найден: ' . $certPath;
        return $results;
    }
    
    if (!file_exists($keyPath)) {
        $results['error'] = 'Файл приватного ключа не найден: ' . $keyPath;
        return $results;
    }
    
    // 1. Проверяем формат сертификата
    $certContent = file_get_contents($certPath);
    if (!preg_match('/-----BEGIN CERTIFICATE-----/', $certContent)) {
        $results['error'] = 'Неверный формат сертификата';
        return $results;
    }
    
    // 2. Проверяем формат приватного ключа
    $keyContent = file_get_contents($keyPath);
    if (!preg_match('/-----BEGIN PRIVATE KEY-----/', $keyContent) && 
        !preg_match('/-----BEGIN RSA PRIVATE KEY-----/', $keyContent)) {
        $results['error'] = 'Неверный формат приватного ключа';
        return $results;
    }
    
    // 3. Проверяем соответствие сертификата и ключа
    $cert = openssl_x509_read($certContent);
    $key = openssl_pkey_get_private($keyContent);
    
    if (!$cert) {
        $results['error'] = 'Не удалось прочитать сертификат';
        return $results;
    }
    
    if (!$key) {
        $results['error'] = 'Не удалось прочитать приватный ключ';
        return $results;
    }
    
    // Проверяем соответствие публичного ключа сертификата и приватного ключа
    $certDetails = openssl_x509_parse($cert);
    $keyDetails = openssl_pkey_get_details($key);
    
    if ($certDetails['signatureTypeSN'] !== $keyDetails['type']) {
        $results['warning'] = 'Тип ключа может не соответствовать сертификату';
    }
    
    // 4. Проверяем срок действия сертификата
    $notBefore = $certDetails['validFrom_time_t'];
    $notAfter = $certDetails['validTo_time_t'];
    $currentTime = time();
    
    $results['valid_from'] = date('Y-m-d H:i:s', $notBefore);
    $results['valid_to'] = date('Y-m-d H:i:s', $notAfter);
    $results['is_expired'] = $currentTime > $notAfter;
    $results['is_not_yet_valid'] = $currentTime < $notBefore;
    $results['days_until_expiry'] = floor(($notAfter - $currentTime) / 86400);
    
    // 5. Проверяем домены в сертификате
    $results['common_name'] = $certDetails['subject']['CN'] ?? 'Не указан';
    $results['subject_alt_names'] = $certDetails['extensions']['subjectAltName'] ?? 'Не указаны';
    
    // 6. Проверяем издателя
    $results['issuer'] = $certDetails['issuer']['O'] ?? 'Неизвестно';
    $results['issuer_cn'] = $certDetails['issuer']['CN'] ?? 'Неизвестно';
    
    // 7. Проверяем цепочку сертификатов (если предоставлена)
    if ($chainPath && file_exists($chainPath)) {
        $chainContent = file_get_contents($chainPath);
        $results['chain_verified'] = verifyCertificateChain($certContent, $chainContent);
    }
    
    // 8. Проверяем криптографические параметры
    $results['signature_algorithm'] = $certDetails['signatureTypeSN'];
    $results['key_size'] = $keyDetails['bits'];
    
    // 9. Проверяем использование ключа
    $results['key_usage'] = $certDetails['extensions']['keyUsage'] ?? 'Не указано';
    $results['extended_key_usage'] = $certDetails['extensions']['extendedKeyUsage'] ?? 'Не указано';
    
    return $results;
}

// Функция для проверки цепочки сертификатов
function verifyCertificateChain($certPem, $chainPem) {
    // Создаем временные файлы для проверки
    $certFile = tempnam(sys_get_temp_dir(), 'cert_');
    $chainFile = tempnam(sys_get_temp_dir(), 'chain_');
    
    file_put_contents($certFile, $certPem);
    file_put_contents($chainFile, $chainPem);
    
    // Используем openssl для проверки цепочки
    $command = "openssl verify -CAfile {$chainFile} {$certFile} 2>&1";
    $output = shell_exec($command);
    
    // Очищаем временные файлы
    unlink($certFile);
    unlink($chainFile);
    
    return strpos($output, 'OK') !== false;
}

// Функция для проверки сертификата через веб-запрос
function verifyCertificateOnline($domain, $port = 443) {
    $context = stream_context_create([
        'ssl' => [
            'capture_peer_cert' => true,
            'verify_peer' => false,
            'verify_peer_name' => false,
        ]
    ]);
    
    $client = @stream_socket_client(
        "ssl://{$domain}:{$port}",
        $errno,
        $errstr,
        30,
        STREAM_CLIENT_CONNECT,
        $context
    );
    
    if (!$client) {
        return ['error' => "Не удалось подключиться к {$domain}:{$port} - {$errstr}"];
    }
    
    $params = stream_context_get_params($client);
    $cert = $params['options']['ssl']['peer_certificate'];
    
    if (!$cert) {
        fclose($client);
        return ['error' => 'Не удалось получить сертификат'];
    }
    
    $certInfo = openssl_x509_parse($cert);
    fclose($client);
    
    return [
        'subject' => $certInfo['subject']['CN'] ?? 'Неизвестно',
        'issuer' => $certInfo['issuer']['O'] ?? 'Неизвестно',
        'valid_from' => date('Y-m-d H:i:s', $certInfo['validFrom_time_t']),
        'valid_to' => date('Y-m-d H:i:s', $certInfo['validTo_time_t']),
        'is_expired' => time() > $certInfo['validTo_time_t'],
        'days_until_expiry' => floor(($certInfo['validTo_time_t'] - time()) / 86400)
    ];
}

// Обработка формы
$verificationResults = [];
$selectedDomain = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $selectedDomain = trim($_POST['domain'] ?? '');
    
    if ($selectedDomain) {
        $certDir = __DIR__ . '/certs/' . $selectedDomain;
        
        if (is_dir($certDir)) {
            $certPath = $certDir . '/cert.pem';
            $keyPath = $certDir . '/privkey.pem';
            $chainPath = $certDir . '/chain.pem';
            $fullchainPath = $certDir . '/fullchain.pem';
            
            // Проверяем локальные файлы
            $verificationResults['local'] = verifyCertificate($certPath, $keyPath, $chainPath);
            
            // Проверяем онлайн (если домен доступен)
            $verificationResults['online'] = verifyCertificateOnline($selectedDomain);
        } else {
            $verificationResults['error'] = 'Директория с сертификатами для домена не найдена';
        }
    }
}

// Получаем список доступных доменов
$availableDomains = [];
$certsDir = __DIR__ . '/certs';
if (is_dir($certsDir)) {
    $domains = scandir($certsDir);
    foreach ($domains as $domain) {
        if ($domain !== '.' && $domain !== '..' && is_dir($certsDir . '/' . $domain)) {
            $availableDomains[] = $domain;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Проверка SSL сертификата</title>
    <link rel="stylesheet" href="style.css">
    <style>
        .verification-section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .verification-section h3 { margin-top: 0; color: #333; }
        .status-ok { color: #28a745; }
        .status-warning { color: #ffc107; }
        .status-error { color: #dc3545; }
        .cert-info { background: #f8f9fa; padding: 10px; border-radius: 3px; margin: 5px 0; }
        .cert-info strong { display: inline-block; width: 150px; }
        .online-check { background: #e7f3ff; padding: 10px; border-radius: 3px; margin: 5px 0; }
    </style>
</head>
<body>
<div class="container">
    <h1>Проверка SSL сертификата</h1>
    
    <form method="post" class="form">
        <div class="form-group">
            <label for="domain">Выберите домен для проверки:</label>
            <select name="domain" id="domain" required>
                <option value="">-- Выберите домен --</option>
                <?php foreach ($availableDomains as $domain): ?>
                    <option value="<?php echo htmlspecialchars($domain); ?>" 
                            <?php echo $selectedDomain === $domain ? 'selected' : ''; ?>>
                        <?php echo htmlspecialchars($domain); ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>
        
        <button type="submit" class="btn btn-primary">Проверить сертификат</button>
    </form>
    
    <?php if (!empty($verificationResults)): ?>
        <div class="verification-section">
            <h3>Результаты проверки для домена: <strong><?php echo htmlspecialchars($selectedDomain); ?></strong></h3>
            
            <?php if (isset($verificationResults['error'])): ?>
                <div class="status-error">
                    <strong>Ошибка:</strong> <?php echo htmlspecialchars($verificationResults['error']); ?>
                </div>
            <?php else: ?>
                <!-- Локальная проверка -->
                <?php if (isset($verificationResults['local'])): ?>
                    <h4>Локальная проверка файлов</h4>
                    <?php $local = $verificationResults['local']; ?>
                    
                    <?php if (isset($local['error'])): ?>
                        <div class="status-error"><?php echo htmlspecialchars($local['error']); ?></div>
                    <?php else: ?>
                        <div class="cert-info">
                            <strong>Общий домен:</strong> <?php echo htmlspecialchars($local['common_name']); ?>
                        </div>
                        
                        <div class="cert-info">
                            <strong>Издатель:</strong> <?php echo htmlspecialchars($local['issuer']); ?>
                        </div>
                        
                        <div class="cert-info">
                            <strong>Действителен с:</strong> <?php echo htmlspecialchars($local['valid_from']); ?>
                        </div>
                        
                        <div class="cert-info">
                            <strong>Действителен до:</strong> 
                            <?php if ($local['is_expired']): ?>
                                <span class="status-error"><?php echo htmlspecialchars($local['valid_to']); ?> (ИСТЕК)</span>
                            <?php elseif ($local['is_not_yet_valid']): ?>
                                <span class="status-warning"><?php echo htmlspecialchars($local['valid_to']); ?> (ЕЩЕ НЕ ДЕЙСТВИТЕЛЕН)</span>
                            <?php else: ?>
                                <span class="status-ok"><?php echo htmlspecialchars($local['valid_to']); ?></span>
                            <?php endif; ?>
                        </div>
                        
                        <div class="cert-info">
                            <strong>Дней до истечения:</strong> 
                            <?php if ($local['days_until_expiry'] < 0): ?>
                                <span class="status-error"><?php echo abs($local['days_until_expiry']); ?> дней назад</span>
                            <?php elseif ($local['days_until_expiry'] < 30): ?>
                                <span class="status-warning"><?php echo $local['days_until_expiry']; ?> дней</span>
                            <?php else: ?>
                                <span class="status-ok"><?php echo $local['days_until_expiry']; ?> дней</span>
                            <?php endif; ?>
                        </div>
                        
                        <div class="cert-info">
                            <strong>Размер ключа:</strong> <?php echo htmlspecialchars($local['key_size']); ?> бит
                        </div>
                        
                        <div class="cert-info">
                            <strong>Алгоритм подписи:</strong> <?php echo htmlspecialchars($local['signature_algorithm']); ?>
                        </div>
                        
                        <?php if (isset($local['chain_verified'])): ?>
                            <div class="cert-info">
                                <strong>Цепочка сертификатов:</strong> 
                                <?php if ($local['chain_verified']): ?>
                                    <span class="status-ok">✅ Проверена</span>
                                <?php else: ?>
                                    <span class="status-error">❌ Ошибка проверки</span>
                                <?php endif; print_r($local); ?>
                            </div>
                        <?php endif; ?>
                        
                        <?php if (isset($local['warning'])): ?>
                            <div class="status-warning">⚠️ <?php echo htmlspecialchars($local['warning']); ?></div>
                        <?php endif; ?>
                    <?php endif; ?>
                <?php endif; ?>
                
                <!-- Онлайн проверка -->
                <?php if (isset($verificationResults['online'])): ?>
                    <h4>Онлайн проверка</h4>
                    <?php $online = $verificationResults['online']; ?>
                    
                    <?php if (isset($online['error'])): ?>
                        <div class="status-error"><?php echo htmlspecialchars($online['error']); ?></div>
                    <?php else: ?>
                        <div class="online-check">
                            <strong>Домен:</strong> <?php echo htmlspecialchars($online['subject']); ?>
                        </div>
                        
                        <div class="online-check">
                            <strong>Издатель:</strong> <?php echo htmlspecialchars($online['issuer']); ?>
                        </div>
                        
                        <div class="online-check">
                            <strong>Действителен с:</strong> <?php echo htmlspecialchars($online['valid_from']); ?>
                        </div>
                        
                        <div class="online-check">
                            <strong>Действителен до:</strong> 
                            <?php if ($online['is_expired']): ?>
                                <span class="status-error"><?php echo htmlspecialchars($online['valid_to']); ?> (ИСТЕК)</span>
                            <?php else: ?>
                                <span class="status-ok"><?php echo htmlspecialchars($online['valid_to']); ?></span>
                            <?php endif; ?>
                        </div>
                        
                        <div class="online-check">
                            <strong>Дней до истечения:</strong> 
                            <?php if ($online['days_until_expiry'] < 0): ?>
                                <span class="status-error"><?php echo abs($online['days_until_expiry']); ?> дней назад</span>
                            <?php elseif ($online['days_until_expiry'] < 30): ?>
                                <span class="status-warning"><?php echo $online['days_until_expiry']; ?> дней</span>
                            <?php else: ?>
                                <span class="status-ok"><?php echo $online['days_until_expiry']; ?> дней</span>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    <?php endif; ?>
    
    <div class="verification-section">
        <h3>💡 Дополнительные способы проверки</h3>
        <p>Вы также можете проверить сертификат с помощью командной строки:</p>
        
        <h4>Проверка сертификата:</h4>
        <pre><code>openssl x509 -in certs/домен/cert.pem -text -noout</code></pre>
        
        <h4>Проверка приватного ключа:</h4>
        <pre><code>openssl rsa -in certs/домен/privkey.pem -check</code></pre>
        
        <h4>Проверка соответствия сертификата и ключа:</h4>
        <pre><code>openssl x509 -noout -modulus -in certs/домен/cert.pem | openssl md5
openssl rsa -noout -modulus -in certs/домен/privkey.pem | openssl md5</code></pre>
        
        <h4>Проверка цепочки сертификатов:</h4>
        <pre><code>openssl verify -CAfile certs/домен/chain.pem certs/домен/cert.pem</code></pre>
        
        <h4>Проверка через веб-сервер:</h4>
        <pre><code>openssl s_client -connect домен:443 -servername домен</code></pre>
    </div>
    
    <p><a href="index.php">⬅ Вернуться на главную</a></p>
</div>
</body>
</html>
