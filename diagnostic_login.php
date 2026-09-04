<?php
/* Safe LibreNMS Login Diagnostic. Delete after troubleshooting. */
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);
header('Content-Type: text/html; charset=utf-8');

$checks = array();
function add_check(&$checks, $name, $ok, $detail) {
    $checks[] = array('name'=>$name, 'ok'=>(bool)$ok, 'detail'=>(string)$detail);
}

add_check($checks, 'PHP version', version_compare(PHP_VERSION, '7.4.0', '>='), PHP_VERSION . ' (minimum recommended 7.4; PHP 8.x preferred)');
add_check($checks, 'PDO extension', extension_loaded('pdo'), extension_loaded('pdo') ? 'Loaded' : 'Not loaded');
add_check($checks, 'PDO MySQL driver', extension_loaded('pdo_mysql'), extension_loaded('pdo_mysql') ? 'Loaded' : 'Not loaded');
add_check($checks, 'Session extension', function_exists('session_start'), function_exists('session_start') ? 'Available' : 'Unavailable');

$sessionOk = false;
$sessionDetail = '';
try {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_name('librenms_bw_diag');
        session_start();
    }
    $_SESSION['diag_test'] = 'ok';
    $sessionOk = isset($_SESSION['diag_test']) && $_SESSION['diag_test'] === 'ok';
    $sessionDetail = 'Session path: ' . session_save_path();
} catch (Throwable $e) {
    $sessionDetail = get_class($e) . ': ' . $e->getMessage();
}
add_check($checks, 'PHP session', $sessionOk, $sessionDetail);

$configFile = __DIR__ . '/auth_config.php';
add_check($checks, 'auth_config.php exists', is_file($configFile), $configFile);
add_check($checks, 'auth_config.php readable', is_readable($configFile), is_readable($configFile) ? 'Readable' : 'Not readable by web server');

$config = null;
if (is_readable($configFile)) {
    try {
        $config = require $configFile;
        add_check($checks, 'auth_config.php format', is_array($config), is_array($config) ? 'Valid PHP array' : 'File did not return an array');
    } catch (Throwable $e) {
        add_check($checks, 'auth_config.php format', false, get_class($e) . ': ' . $e->getMessage());
    }
}

if (is_array($config) && extension_loaded('pdo_mysql')) {
    $host = isset($config['host']) ? (string)$config['host'] : '';
    $port = isset($config['port']) ? (int)$config['port'] : 3306;
    $db   = isset($config['database']) ? (string)$config['database'] : '';
    $user = isset($config['username']) ? (string)$config['username'] : '';
    $pass = isset($config['password']) ? (string)$config['password'] : '';
    add_check($checks, 'Auth configuration fields', $host !== '' && $db !== '' && $user !== '' && $pass !== '', 'Host=' . $host . '; Port=' . $port . '; Database=' . $db . '; User=' . $user . '; Password=' . ($pass !== '' ? '[SET]' : '[EMPTY]'));
    try {
        $dsn = 'mysql:host=' . $host . ';port=' . $port . ';dbname=' . $db . ';charset=utf8mb4';
        $pdo = new PDO($dsn, $user, $pass, array(PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC));
        add_check($checks, 'Authentication DB connection', true, 'Connected as ' . $user . ' to ' . $db);
        $dbCurrent = (string)$pdo->query('SELECT DATABASE()')->fetchColumn();
        add_check($checks, 'Selected database', $dbCurrent === $db, 'Current database: ' . $dbCurrent);
        $st = $pdo->prepare("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=? AND table_name='dashboard_users'");
        $st->execute(array($db));
        $tableExists = ((int)$st->fetchColumn() === 1);
        add_check($checks, 'dashboard_users table', $tableExists, $tableExists ? 'Table exists' : 'Table is missing');
        if ($tableExists) {
            $count = (int)$pdo->query('SELECT COUNT(*) FROM dashboard_users')->fetchColumn();
            $admins = (int)$pdo->query("SELECT COUNT(*) FROM dashboard_users WHERE role='admin' AND is_active=1")->fetchColumn();
            add_check($checks, 'Dashboard users', $count > 0, 'Total users: ' . $count);
            add_check($checks, 'Active administrator', $admins > 0, 'Active admins: ' . $admins);
            $cols = $pdo->query("SHOW COLUMNS FROM dashboard_users")->fetchAll(PDO::FETCH_COLUMN);
            $required = array('id','username','password_hash','full_name','role','is_active','last_login','created_at','updated_at');
            $missing = array_values(array_diff($required, $cols));
            add_check($checks, 'Required columns', count($missing) === 0, count($missing) ? 'Missing: ' . implode(', ', $missing) : 'All required columns exist');
        }
    } catch (Throwable $e) {
        add_check($checks, 'Authentication DB connection', false, get_class($e) . ': ' . $e->getMessage());
    }
}

$allOk = true;
foreach ($checks as $c) { if (!$c['ok']) { $allOk = false; break; } }
?><!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login Diagnostic</title><style>
*{box-sizing:border-box}body{margin:0;padding:25px;background:#071722;color:#dff4fb;font:14px Arial,sans-serif}.wrap{max-width:980px;margin:auto}.head{padding:22px;border:1px solid #264b5d;border-radius:16px;background:linear-gradient(135deg,#0c3245,#104d64)}h1{margin:0 0 8px}.status{display:inline-block;margin-top:8px;padding:7px 11px;border-radius:999px;font-weight:bold;background:<?php echo $allOk?'#087a59':'#a62d3e';?>}.list{margin-top:14px;display:grid;gap:9px}.row{display:grid;grid-template-columns:40px 230px 1fr;gap:10px;align-items:start;padding:13px;border:1px solid #264554;border-radius:11px;background:#0d2632}.icon{width:28px;height:28px;display:grid;place-items:center;border-radius:50%;font-weight:bold;background:#a62d3e}.ok .icon{background:#087a59}.name{font-weight:bold}.detail{color:#a9c5d1;word-break:break-word}.note{margin-top:16px;padding:14px;border:1px solid #6e5929;border-radius:11px;color:#f5d68a;background:#322a16}code{color:#9ce8ff}@media(max-width:650px){.row{grid-template-columns:40px 1fr}.detail{grid-column:2}.name{padding-top:6px}}</style></head><body><div class="wrap"><div class="head"><h1>LibreNMS Login Diagnostic</h1><div>File ini memeriksa PHP, session, konfigurasi, database autentikasi, tabel, dan akun Admin tanpa menampilkan password.</div><span class="status"><?php echo $allOk?'ALL CHECKS PASSED':'PROBLEM DETECTED';?></span></div><div class="list"><?php foreach($checks as $c):?><div class="row <?php echo $c['ok']?'ok':'bad';?>"><div class="icon"><?php echo $c['ok']?'OK':'X';?></div><div class="name"><?php echo htmlspecialchars($c['name'],ENT_QUOTES,'UTF-8');?></div><div class="detail"><?php echo htmlspecialchars($c['detail'],ENT_QUOTES,'UTF-8');?></div></div><?php endforeach;?></div><div class="note"><b>Penting:</b> screenshot bagian yang bertanda merah, lalu hapus file <code>diagnostic_login.php</code> setelah troubleshooting selesai.</div></div></body></html>
