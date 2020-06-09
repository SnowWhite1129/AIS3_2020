<?php

    // Settings
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);
    date_default_timezone_set('Asia/Taipei');
    session_start();

    if ($action = @$_GET['action']) {
        function redirect($path = '/', $message = null) {
            $alert = $message ? 'alert(' . json_encode($message) . ')' : '';
            $path = json_encode($path);
            die("<script>$alert; document.location.replace($path);</script>");
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

?>

