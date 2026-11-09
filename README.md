# PoC-Modified-Shop

## Deploy Enviroment
Update and Upgrade Linnux host
```
sudo apt update && sudo apt upgrade -y
```

Install Docker and Docker Compose
```
sudo apt install -y docker.io docker-compose
```

Create Folder and Navigate to Directory
```
mkdir modified-shop-web && cd modified-shop-web
```

Download Docker File
```
wget https://raw.githubusercontent.com/smithbraz/PoC-Modified-Shop/refs/heads/main/docker-compose.yml
```

Create Config File
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

include_once dirname(_DIR_) . '/configure.php';

```


Deploy WebApp
```
sudo docker compose up
```
or 
```
sudo docker compose up -d
```


