# PHP Let's Encrypt Certificate Generator

Простой веб-интерфейс для генерации SSL-сертификатов Let's Encrypt с использованием HTTP-01 проверки.

## Возможности

- Выпуск сертификатов Let's Encrypt через веб-интерфейс
- Поддержка нескольких доменов (SAN-сертификаты)
- Поддержка тестового (staging) и производственного серверов Let's Encrypt
- Автоматическое решение HTTP-01 challenge
- Сохранение сертификатов в формате, совместимом с Nginx и Apache

## Требования

- PHP 7.2 или выше
- Модули PHP: OpenSSL, cURL, JSON
- Доступ на запись к директории веб-сервера (для размещения файлов проверки)
- Доступ на запись к директории приложения (для сохранения сертификатов)

## Установка

1. Клонируйте репозиторий:
```
git clone https://github.com/yourusername/php-letsencrypt-generator.git
cd php-letsencrypt-generator
```

2. Установите зависимости через Composer:
```
composer install
```

3. Убедитесь, что директории `storage/keys` и `certs` доступны для записи:
```
mkdir -p storage/keys certs
chmod 700 storage/keys certs
```

4. Настройте веб-сервер для доступа к приложению (Apache, Nginx и т.д.)

## Использование

1. Откройте приложение в браузере
2. Заполните форму:
   - **Домены**: Укажите один или несколько доменов через запятую (например, `example.com, www.example.com`)
   - **Email**: Укажите ваш email для регистрации в Let's Encrypt
   - **Путь к корню сайта**: Укажите полный путь к корню веб-сервера, где будут размещены файлы проверки
   - **Использовать тестовый сервер**: Отметьте для использования тестового сервера Let's Encrypt (рекомендуется для тестирования)

3. Нажмите "Выпустить сертификат"
4. Дождитесь завершения процесса
5. Скачайте сгенерированные файлы сертификатов

## Структура сертификатов

После успешного выпуска сертификата в директории `certs/[domain]` будут созданы следующие файлы:

- `privkey.pem` - Приватный ключ
- `cert.pem` - Сертификат домена
- `chain.pem` - Цепочка сертификатов CA
- `fullchain.pem` - Полная цепочка (сертификат + цепочка CA)

## Настройка веб-серверов

### Nginx

```nginx
server {
    listen 443 ssl;
    server_name example.com www.example.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    # Дополнительные настройки SSL
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    
    # Остальные настройки сервера
    # ...
}
```

### Apache

```apache
<VirtualHost *:443>
    ServerName example.com
    ServerAlias www.example.com
    
    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/privkey.pem
    SSLCertificateChainFile /path/to/chain.pem
    
    # Остальные настройки виртуального хоста
    # ...
</VirtualHost>
```

## Автоматическое обновление

Сертификаты Let's Encrypt действительны в течение 90 дней. Для автоматического обновления рекомендуется настроить задачу cron.

## Безопасность

- Не размещайте этот инструмент в публичном доступе без дополнительной защиты (например, HTTP-аутентификация)
- Убедитесь, что директории `storage/keys` и `certs` не доступны через веб
- Ограничьте права доступа к файлам сертификатов

## Лицензия

MIT
