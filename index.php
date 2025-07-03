<?php
// index.php – Simple UI to request Let's Encrypt certificates
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Генератор сертификатов Let's Encrypt</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="container">
    <h1>Генератор сертификатов Let's Encrypt</h1>

    <form action="generate.php" method="POST">
        <label for="domains">Домен(ы) (через запятую):</label>
        <input type="text" id="domains" name="domains" placeholder="example.com, www.example.com" required>

        <label for="email">E-mail для Let's Encrypt:</label>
        <input type="email" id="email" name="email" placeholder="admin@example.com" required>

        <label for="webroot">Путь к корню сайта (document root):</label>
        <input type="text" id="webroot" name="webroot" placeholder="/var/www/html" required>

        <button type="submit">Выпустить сертификат</button>
    </form>
</div>
</body>
</html> 