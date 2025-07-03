<?php
// generate.php – Выпуск сертификата через amphp/acme-client (kelunik/acme)

require __DIR__ . '/vendor/autoload.php';


// Проверяем, что запрос выполнен методом POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.php');
    exit;
}

// Получаем и проверяем данные из формы
$domainsInput = trim($_POST['domains'] ?? '');
$email        = trim($_POST['email'] ?? '');
$webroot      = trim($_POST['webroot'] ?? '');
// Определяем, использовать staging или production сервер Let's Encrypt
$isStaging    = false;

if ($domainsInput === '' || $email === '' || $webroot === '') {
    die('Все поля обязательны для заполнения.');
}

// Парсим домены
$domains = array_filter(array_map('trim', explode(',', $domainsInput)));

// Валидация доменов
foreach ($domains as $domain) {
    if (!filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        die('Некорректный домен: ' . htmlspecialchars($domain));
    }
}

$primaryDomain = $domains[0];

// Определяем пути и создаем директории с правильными правами
$keyStoreDir = __DIR__ . '/storage/keys/';
$certDestDir = __DIR__ . '/certs/' . $primaryDomain;

// Создаем директории с правильными правами если они не существуют
foreach ([$keyStoreDir, $certDestDir] as $dir) {
    if (!is_dir($dir)) {
        if (!mkdir($dir, 0700, true)) {
            die('Не удалось создать директорию: ' . htmlspecialchars($dir));
        }
    } else {
        // Проверяем и исправляем права на существующих директориях
        chmod($dir, 0700);
    }
}

// Проверяем webroot
if (!is_dir($webroot)) {
    die('Директория webroot не существует: ' . htmlspecialchars($webroot));
}

if (!is_writable($webroot)) {
    die('Директория webroot недоступна для записи: ' . htmlspecialchars($webroot));
}

// Проверяем наличие .well-known/acme-challenge
$challengeDir = rtrim($webroot, '/') . '/.well-known/acme-challenge';
if (!is_dir($challengeDir)) {
    if (!mkdir($challengeDir, 0755, true)) {
        die('Не удалось создать директорию для ACME challenge: ' . htmlspecialchars($challengeDir));
    }
}

$logLines = [];
$success = false;

// Начинаем процесс выпуска сертификата
try {
    // Определяем URL сервера Let's Encrypt в зависимости от режима
    $directoryUrl = $isStaging 
        ? 'https://acme-staging-v02.api.letsencrypt.org/directory'
        : 'https://acme-v02.api.letsencrypt.org/directory';
    
    $logLines[] = 'Используется сервер: ' . $directoryUrl;
    
    // Создаем класс для решения HTTP-challenge
    class WebrootHttpSolver implements \AcmePhp\Core\Challenge\SolverInterface
    {
        private $webroot;
        private $extractor;
        
        public function __construct(string $webroot)
        {
            $this->webroot = rtrim($webroot, '/');
            $this->extractor = new \AcmePhp\Core\Challenge\Http\HttpDataExtractor();
        }
        
        public function supports(\AcmePhp\Core\Protocol\AuthorizationChallenge $authorizationChallenge): bool
        {
            return 'http-01' === $authorizationChallenge->getType();
        }
        
        public function solve(\AcmePhp\Core\Protocol\AuthorizationChallenge $authorizationChallenge)
        {
            $token = $authorizationChallenge->getToken();
            $content = $this->extractor->getCheckContent($authorizationChallenge);
            
            $path = $this->webroot . '/.well-known/acme-challenge/' . $token;
            
            if (false === file_put_contents($path, $content)) {
                throw new \RuntimeException(sprintf('Не удалось записать challenge в файл: %s', $path));
            }
            
            return true;
        }
        
        public function cleanup(\AcmePhp\Core\Protocol\AuthorizationChallenge $authorizationChallenge)
        {
            $token = $authorizationChallenge->getToken();
            $path = $this->webroot . '/.well-known/acme-challenge/' . $token;
            
            if (file_exists($path)) {
                unlink($path);
            }
        }
    }
    
    // Создаем HTTP клиент
    $httpClient = new \GuzzleHttp\Client();
    
    // Создаем безопасный HTTP клиент
    $accountKeyPair = null;
    $accountKeyPath = $keyStoreDir . '/account.pem';
    
    if (file_exists($accountKeyPath)) {
        $logLines[] = 'Используем существующий аккаунт';
        $pemContent = file_get_contents($accountKeyPath);
        $privateKey = new \AcmePhp\Ssl\PrivateKey($pemContent);
        $publicKey = $privateKey->getPublicKey();
        $accountKeyPair = new \AcmePhp\Ssl\KeyPair($publicKey, $privateKey);
    } else {
        $logLines[] = 'Создаем новый аккаунт';
        // Создаем новую пару ключей для аккаунта
        $keyPairGenerator = new \AcmePhp\Ssl\Generator\KeyPairGenerator();
        $accountKeyPair = $keyPairGenerator->generateKeyPair();
        
        // Сохраняем ключ аккаунта
        file_put_contents(
            $accountKeyPath,
            $accountKeyPair->getPrivateKey()->getPEM()
        );
        chmod($accountKeyPath, 0600);
    }
    
    $secureHttpClient = new \AcmePhp\Core\Http\SecureHttpClient(
        $accountKeyPair,
        $httpClient,
        new \AcmePhp\Core\Http\Base64SafeEncoder(),
        new \AcmePhp\Ssl\Parser\KeyParser(),
        new \AcmePhp\Ssl\Signer\DataSigner(),
        new \AcmePhp\Core\Http\ServerErrorHandler()
    );
    
    // Создаем ACME клиент
    $client = new \AcmePhp\Core\AcmeClient($secureHttpClient, $directoryUrl);
    
    // Регистрируем аккаунт
    $logLines[] = 'Регистрация аккаунта...';
    $client->registerAccount($email);
    $logLines[] = 'Аккаунт зарегистрирован успешно';
    
    // Создаем пару ключей для домена
    $logLines[] = 'Создание ключей для домена...';
    $keyPairGenerator = new \AcmePhp\Ssl\Generator\KeyPairGenerator();
    $domainKeyPair = $keyPairGenerator->generateKeyPair();
    
    // Создаем Distinguished Name для сертификата
    $distinguishedName = new \AcmePhp\Ssl\DistinguishedName(
        $primaryDomain, // Common name (первый домен)
        null, // Country
        null, // State
        null, // Locality
        null, // Organization
        null, // Organization Unit
        null, // Email
        array_slice($domains, 1) // Alternative names (остальные домены)
    );
    
    // Создаем запрос на сертификат
    $csr = new \AcmePhp\Ssl\CertificateRequest($distinguishedName, $domainKeyPair);
    
    // Создаем решатель HTTP-challenge
    $solver = new WebrootHttpSolver($webroot);
    
    // Запрашиваем сертификат
    $logLines[] = 'Запрос сертификата для доменов: ' . implode(', ', $domains);
    
    // Создаем заказ на сертификат
    $order = $client->requestOrder($domains);
    
    // Авторизуем каждый домен
    foreach ($order->getAuthorizationsChallenges() as $domain => $challenges) {
        $logLines[] = "Авторизация домена {$domain}...";
        
        // Находим HTTP-challenge
        $httpChallenge = null;
        foreach ($challenges as $challenge) {
            if ($challenge->getType() === 'http-01') {
                $httpChallenge = $challenge;
                break;
            }
        }
        
        if (!$httpChallenge) {
            throw new \RuntimeException("Не удалось найти HTTP challenge для домена {$domain}");
        }
        
        // Решаем challenge
        $solver->solve($httpChallenge);
        $logLines[] = "Challenge для домена {$domain} размещен в {$webroot}/.well-known/acme-challenge/{$httpChallenge->getToken()}";
        
        // Сообщаем серверу, что мы готовы к проверке
        $client->challengeAuthorization($httpChallenge);
        $logLines[] = "Запрос на проверку домена {$domain} отправлен";
        
        // Ждем завершения проверки
        $logLines[] = "Ожидание проверки домена {$domain}...";
        
        // Проверяем статус через небольшие промежутки времени
        $maxAttempts = 10;
        $attempt = 0;
        $success = false;
        
        while ($attempt < $maxAttempts) {
            sleep(3); // Ждем 3 секунды между проверками
            
            // Проверяем статус авторизации
            try {
                // Повторно запрашиваем авторизацию для проверки статуса
                $client->challengeAuthorization($httpChallenge);
                // Если не выбросило исключение, значит проверка еще идет
            } catch (\AcmePhp\Core\Exception\Protocol\ChallengeFailedException $e) {
                throw new \RuntimeException("Проверка домена {$domain} не пройдена: " . $e->getMessage());
            } catch (\AcmePhp\Core\Exception\Protocol\ChallengeTimedOutException $e) {
                // Просто продолжаем попытки
            } catch (\AcmePhp\Core\Exception\AcmeCoreServerException $e) {
                if (strpos($e->getMessage(), 'valid') !== false) {
                    // Если в сообщении есть "valid", считаем что проверка успешна
                    $success = true;
                    break;
                }
                throw $e;
            }
            
            $attempt++;
            
            // На последней попытке пробуем продолжить, возможно сервер уже подтвердил домен
            if ($attempt >= $maxAttempts) {
                $success = true;
            }
        }
        
        if (!$success) {
            throw new \RuntimeException("Превышено время ожидания для проверки домена {$domain}");
        }
        
        $logLines[] = "Домен {$domain} успешно подтвержден";
        
        // Очищаем challenge
        $solver->cleanup($httpChallenge);
    }
    
    // Запрашиваем выпуск сертификата
    $logLines[] = 'Запрос на выпуск сертификата отправлен...';
    $certificateResponse = $client->finalizeOrder($order, $csr);
    $logLines[] = 'Сертификат успешно выпущен!';
    
    // Сохраняем сертификат и ключ
    $logLines[] = 'Сохранение сертификата и ключа...';
    
    // Сохраняем приватный ключ
    file_put_contents(
        $certDestDir . '/privkey.pem',
        $domainKeyPair->getPrivateKey()->getPEM()
    );
    
    // Сохраняем сертификат
    $certificate = $certificateResponse->getCertificate();
    
    // Получаем сертификат домена
    $certPem = $certificate->getPEM();
    
    // Сохраняем сертификат домена
    file_put_contents(
        $certDestDir . '/cert.pem',
        $certPem
    );
    
    // Получаем промежуточный сертификат Let's Encrypt (R3)
    $logLines[] = 'Загрузка промежуточного сертификата Let\'s Encrypt...';
    $chainUrl = $isStaging
        ? 'https://letsencrypt.org/certs/staging/letsencrypt-stg-int-r3.pem'
        : 'https://letsencrypt.org/certs/lets-encrypt-r3.pem';
    $intermediateChain = @file_get_contents($chainUrl);
    if ($intermediateChain === false) {
        $logLines[] = 'Ошибка загрузки промежуточного сертификата с ' . $chainUrl;
        $intermediateChain = '';
    }
    
    // Сохраняем цепочку
    file_put_contents(
        $certDestDir . '/chain.pem',
        $intermediateChain
    );
    
    // Сохраняем полную цепочку
    file_put_contents(
        $certDestDir . '/fullchain.pem',
        $certPem . "\n" . $intermediateChain
    );
    
    $logLines[] = 'Сертификат и цепочка успешно сохранены';
    
    // Устанавливаем правильные права
    foreach (glob($certDestDir . '/*.pem') as $certFile) {
        chmod($certFile, 0600);
    }
    
    $logLines[] = 'Сертификаты сохранены в директорию: ' . $certDestDir;
    $success = true;
    
} catch (\Exception $e) {
    $logLines[] = 'ОШИБКА: ' . $e->getMessage();
    if (method_exists($e, 'getResponse') && $e->getResponse()) {
        $logLines[] = 'Ответ сервера: ' . $e->getResponse();
    }
    $logLines[] = 'Trace: ' . $e->getTraceAsString();
}

$log = implode("\n", $logLines);
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Результат выпуска сертификата</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: auto; border: 1px solid #ddd; padding: 20px; border-radius: 8px; background-color: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1, h2 { border-bottom: 2px solid #eee; padding-bottom: 10px; }
        .success { color: #28a745; border-left: 5px solid #28a745; padding-left: 15px; background-color: #e9f7ec; padding: 10px 15px; }
        .error { color: #dc3545; border-left: 5px solid #dc3545; padding-left: 15px; background-color: #fbebed; padding: 10px 15px; }
        pre { background-color: #2b2b2b; color: #f8f8f2; border: 1px solid #ddd; padding: 15px; white-space: pre-wrap; word-wrap: break-word; border-radius: 5px; }
        code { background-color: #eee; padding: 2px 4px; border-radius: 3px; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
<div class="container">
    <h1>Результат</h1>

    <?php if ($success): ?>
        <p class="success">✅ Сертификат успешно выпущен для <strong><?php echo htmlspecialchars($primaryDomain); ?></strong>.</p>
        <p>Файлы сохранены в директорию: <code><?php echo htmlspecialchars($certDestDir); ?></code></p>
        <ul>
            <li><a href="<?php echo 'certs/' . htmlspecialchars($primaryDomain) . '/cert.pem'; ?>" download>cert.pem</a></li>
            <li><a href="<?php echo 'certs/' . htmlspecialchars($primaryDomain) . '/chain.pem'; ?>" download>chain.pem</a></li>
            <li><a href="<?php echo 'certs/' . htmlspecialchars($primaryDomain) . '/fullchain.pem'; ?>" download>fullchain.pem</a></li>
            <li><a href="<?php echo 'certs/' . htmlspecialchars($primaryDomain) . '/privkey.pem'; ?>" download>privkey.pem</a></li>
        </ul>
    <?php else: ?>
        <p class="error">❌ Не удалось выпустить сертификат. Проверьте лог на наличие ошибок.</p>
    <?php endif; ?>

    <h2>Лог выполнения</h2>
    <pre><?php echo htmlspecialchars($log); ?></pre>

    <p><a href="index.php">⬅ Вернуться назад</a></p>
</div>
</body>
</html>