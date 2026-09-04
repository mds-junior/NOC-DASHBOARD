<?php
/*
 LibreNMS Bandwidth Dashboard Single PHP v44 - Living Dashboard Visual System
 - Custom port selector from UI
 - Live graph from LibreNMS DB
 - History graph from RRD via SSH
 - Quick ranges + custom date/time like Zabbix
*/

// ===================== LOGIN / SESSION =====================
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_name('librenms_bw_session');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}

function auth_user(): ?array {
    return isset($_SESSION['auth_user']) && is_array($_SESSION['auth_user']) ? $_SESSION['auth_user'] : null;
}
function auth_is_admin(): bool {
    return (auth_user()['role'] ?? '') === 'admin';
}
function auth_csrf(): string {
    if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf_token'];
}
function auth_require_login(bool $json=false): void {
    if (auth_user()) return;
    if ($json) jout(['error'=>'Sesi login habis. Silakan login ulang.','login_required'=>true],401);
    header('Location: ?page=login'); exit;
}
function auth_require_admin(): void {
    auth_require_login(true);
    if (!auth_is_admin()) jout(['error'=>'Akses ditolak. Fitur ini hanya untuk role admin.'],403);
}
function auth_check_csrf(): void {
    $token=(string)($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf_token'] ?? ''));
    if ($token==='' || !hash_equals(auth_csrf(),$token)) jout(['error'=>'CSRF token tidak valid. Refresh halaman lalu coba lagi.'],419);
}
// ===========================================================

// ===================== AUTH DATABASE CONFIG =====================
define('AUTH_CONFIG_FILE', __DIR__ . '/auth_config.php');
if (!is_file(AUTH_CONFIG_FILE)) {
    if (!isset($_GET['api'])) { header('Location: install.php'); exit; }
    http_response_code(503); header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error'=>'Dashboard belum di-setup. Buka install.php.']); exit;
}
$AUTH_CONFIG = require AUTH_CONFIG_FILE;
if (!is_array($AUTH_CONFIG)) { http_response_code(500); exit('auth_config.php tidak valid: file harus return array.'); }
define('AUTH_DB_HOST', (string)($AUTH_CONFIG['host'] ?? '10.100.108.250'));
define('AUTH_DB_PORT', (int)($AUTH_CONFIG['port'] ?? 3306));
define('AUTH_DB_NAME', (string)($AUTH_CONFIG['database'] ?? 'librenms_dashboard'));
define('AUTH_DB_USER', (string)($AUTH_CONFIG['username'] ?? 'dashboard_app'));
define('AUTH_DB_PASS', (string)($AUTH_CONFIG['password'] ?? ''));
// =================================================================

// ===================== CONFIG =====================
define('DB_HOST', '10.100.108.32');
define('DB_PORT', 3306);
define('DB_NAME', 'librenms');
define('DB_USER', 'admin');       // <-- ganti kalau beda
define('DB_PASS', '@Mdsjunior08');      // <-- isi password DB LibreNMS


define('REFRESH_SECONDS', 5);
define('TOP_LIMIT', 12);

define('RRD_BASE', '/opt/librenms/rrd');
define('RRDTOOL_BIN', '/usr/bin/rrdtool');
define('HISTORY_METHOD', 'ssh');
define('RRD_SSH_HOST', '10.100.108.32');
define('RRD_SSH_USER', 'librenms');
define('RRD_SSH_PORT', 8008);
define('RRD_SSH_KEY', '/var/www/.ssh/id_rsa');
define('RRD_SSH_HOME', '/var/www');

// Port default saat pertama buka browser. Isi port_id kalau mau.
$DEFAULT_PORT_IDS = [];

// Grouping per cabang/lokasi. Isi port_id sesuai kebutuhan.
// Contoh: 'BANGKA' => [1431,270], 'DC' => [2503]
$GROUPS = [
    'ALL / SAVED' => [],
    'BANGKA' => [],
    'DC' => [],
    'DRC' => [],
    'HO' => [],
];
$EXCLUDE_IFTYPES = ['softwareLoopback', 'propVirtual', 'l2vlan', 'tunnel'];
// ==================================================

function auth_db(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;
    $dsn='mysql:host='.AUTH_DB_HOST.';port='.AUTH_DB_PORT.';dbname='.AUTH_DB_NAME.';charset=utf8mb4';
    $pdo=new PDO($dsn,AUTH_DB_USER,AUTH_DB_PASS,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC,PDO::ATTR_EMULATE_PREPARES=>false]);
    return $pdo;
}

function db(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;
    $dsn = 'mysql:host=' . DB_HOST . ';port=' . DB_PORT . ';dbname=' . DB_NAME . ';charset=utf8mb4';
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES=>false]);
    return $pdo;
}
function auth_login_attempt(): void {
    $username=trim((string)($_POST['username'] ?? ''));
    $password=(string)($_POST['password'] ?? '');
    if ($username==='' || $password==='') { $_SESSION['login_error']='Username dan password wajib diisi.'; header('Location: ?page=login'); exit; }
    try {
        $st=auth_db()->prepare("SELECT id,username,password_hash,full_name,role,is_active FROM dashboard_users WHERE username=? LIMIT 1");
        $st->execute([$username]); $u=$st->fetch();
        if (!$u || !(int)$u['is_active'] || !password_verify($password,(string)$u['password_hash'])) {
            usleep(350000); $_SESSION['login_error']='Username atau password salah.'; header('Location: ?page=login'); exit;
        }
        session_regenerate_id(true);
        $_SESSION['auth_user']=['id'=>(int)$u['id'],'username'=>$u['username'],'full_name'=>$u['full_name'],'role'=>$u['role']];
        $_SESSION['csrf_token']=bin2hex(random_bytes(32));
        auth_db()->prepare("UPDATE dashboard_users SET last_login=NOW() WHERE id=?")->execute([(int)$u['id']]);
        header('Location: librenms.php'); exit;
    } catch (Throwable $e) {
        error_log('LibreNMS auth login error: '.$e->getMessage()); $_SESSION['login_error']='Koneksi database login bermasalah. Hubungi administrator.';
        header('Location: ?page=login'); exit;
    }
}
function auth_logout(): void {
    $_SESSION=[];
    if (ini_get('session.use_cookies')) { $p=session_get_cookie_params(); setcookie(session_name(),'',time()-42000,$p['path'],$p['domain']??'',(bool)$p['secure'],(bool)$p['httponly']); }
    session_destroy(); header('Location: ?page=login'); exit;
}
function render_login_page(): void {
    if (auth_user()) { header('Location: librenms.php'); exit; }
    $error=(string)($_SESSION['login_error'] ?? ''); unset($_SESSION['login_error']);
    $safe=htmlspecialchars($error,ENT_QUOTES,'UTF-8');
    echo '<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login Bandwidth Command Center</title><style>
    *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;font-family:Arial,sans-serif;color:#17384d;background:radial-gradient(circle at 15% 10%,rgba(45,140,255,.25),transparent 34%),radial-gradient(circle at 88% 84%,rgba(245,158,11,.20),transparent 30%),linear-gradient(135deg,#061723,#0b3448 55%,#102535)}
    .login-shell{width:min(940px,100%);display:grid;grid-template-columns:1.1fr .9fr;overflow:hidden;border:1px solid rgba(171,224,244,.28);border-radius:24px;background:rgba(8,31,44,.82);box-shadow:0 30px 90px rgba(0,0,0,.42);backdrop-filter:blur(18px)}.hero{padding:56px;color:#e9f9ff;background:linear-gradient(145deg,rgba(19,100,128,.62),rgba(12,42,60,.45))}.mark{width:64px;height:64px;display:grid;place-items:center;border-radius:18px;font-size:30px;background:linear-gradient(145deg,#2d8cff,#16b8ca);box-shadow:0 12px 34px rgba(45,140,255,.34)}h1{margin:24px 0 10px;font-size:32px}.hero p{color:#b8d8e4;line-height:1.65}.bullet{margin-top:28px;display:grid;gap:10px}.bullet span{padding:10px 12px;border:1px solid rgba(176,229,245,.14);border-radius:10px;background:rgba(255,255,255,.05)}.form{padding:52px 44px;background:#f7fbfd}.form h2{margin:0 0 7px;font-size:25px}.sub{margin:0 0 27px;color:#718896}.field{margin-bottom:16px}.field label{display:block;margin-bottom:7px;font-weight:800;font-size:11px;letter-spacing:.5px}.field input{width:100%;height:48px;padding:0 14px;border:1px solid #cbdde7;border-radius:11px;background:#fff;font-size:14px}.field input:focus{outline:0;border-color:#2d8cff;box-shadow:0 0 0 4px rgba(45,140,255,.12)}button{width:100%;height:49px;margin-top:7px;border:0;border-radius:11px;color:#fff;font-weight:900;font-size:14px;cursor:pointer;background:linear-gradient(135deg,#176fd2,#2d8cff 55%,#0ca6b8);box-shadow:0 10px 24px rgba(45,140,255,.25)}.error{margin-bottom:16px;padding:11px;border:1px solid #efb3bb;border-radius:9px;color:#a72839;background:#fff0f2}.foot{margin-top:20px;text-align:center;color:#8197a3;font-size:11px}@media(max-width:760px){.login-shell{grid-template-columns:1fr}.hero{display:none}.form{padding:36px 25px}}
/* ===== v49 MySQL Login + Role Access ===== */
.user-session{display:flex;align-items:center;gap:8px;padding:6px 8px 6px 11px;border:1px solid rgba(255,255,255,.16);border-radius:11px;background:rgba(255,255,255,.07)}.user-session strong{font-size:11px;color:#e8f8ff}.role-pill{padding:3px 7px;border-radius:999px;font-size:8px;font-weight:900;letter-spacing:.6px;background:#2d8cff;color:#fff}.role-pill.viewer{background:#f59e0b}.logout-link{padding:5px 8px;border-radius:7px;color:#fff;text-decoration:none;font-size:10px;font-weight:800;background:rgba(230,72,88,.76)}body.role-viewer .admin-only{display:none!important}body.role-viewer .card-head{cursor:default!important}body.role-viewer .drag-hint,body.role-viewer .resize-handle,body.role-viewer .size-tools,body.role-viewer .layout-tools,body.role-viewer .tools>button{display:none!important}body.role-viewer .card-head .title:after{content:" VIEW ONLY";color:#a36500;background:#fff0cf}.viewer-notice{display:none;margin:8px 12px 0;padding:8px 11px;border:1px solid #f0d18d;border-radius:10px;color:#825400;background:#fff7e6;font-weight:700}body.role-viewer .viewer-notice{display:block}


/* ===== v50 Admin User Management ===== */
.user-manage-btn{height:34px;padding:0 12px;border:1px solid rgba(255,255,255,.22);border-radius:8px;color:#fff;background:linear-gradient(135deg,#176fd2,#2d8cff);font-size:10px;font-weight:900;cursor:pointer}.user-modal{display:none;position:fixed;inset:0;z-index:50000;padding:22px;background:rgba(3,15,24,.74);backdrop-filter:blur(8px)}.user-modal.open{display:grid;place-items:center}.user-dialog{width:min(1040px,98vw);max-height:92vh;display:flex;flex-direction:column;overflow:hidden;border:1px solid #b9d8e6;border-radius:19px;background:#f6fafc;box-shadow:0 32px 90px rgba(0,0,0,.45)}.user-dialog-head{display:flex;align-items:center;justify-content:space-between;padding:16px 18px;color:#fff;background:linear-gradient(120deg,#082b3e,#0b6d82 55%,#2d70d7)}.user-dialog-head h2{margin:3px 0 0;font-size:18px}.user-dialog-head small{color:#aee5f0;font-size:8px;letter-spacing:1px}.user-dialog-head button{width:34px;height:34px;border:1px solid rgba(255,255,255,.25);border-radius:9px;background:rgba(255,255,255,.1);color:#fff;font-size:20px;cursor:pointer}.user-create{display:grid;grid-template-columns:1fr 1.35fr 1fr .75fr auto;gap:8px;padding:13px;border-bottom:1px solid #d6e5ec;background:#edf6fa}.user-create input,.user-create select,.user-create button,.user-row input,.user-row select,.user-row button{height:36px;border:1px solid #c5d9e4;border-radius:8px;padding:0 9px}.user-create button{border:0;padding:0 15px;color:#fff;font-weight:900;background:#087ca8;cursor:pointer}.user-list{padding:12px;overflow:auto}.user-row{display:grid;grid-template-columns:55px 1fr 1.4fr .75fr 90px 150px 230px;gap:7px;align-items:center;margin-bottom:7px;padding:8px;border:1px solid #dbe7ed;border-radius:10px;background:#fff}.user-row.header{position:sticky;top:-12px;z-index:2;color:#6c8290;font-size:9px;font-weight:900;background:#eef5f8}.user-status{font-size:9px;font-weight:900}.user-status.on{color:#07845f}.user-status.off{color:#c0392b}.user-actions{display:flex;gap:5px}.user-actions button{height:30px;padding:0 8px;font-size:9px;font-weight:800;cursor:pointer;background:#eef6fb;color:#315d73}.user-actions .danger{color:#fff;border-color:#c43e4d;background:#d94b5a}.user-message{min-height:35px;padding:10px 14px;color:#617985;background:#f5fafc}.user-message.error{color:#a72839;background:#fff0f2}@media(max-width:850px){.user-create{grid-template-columns:1fr 1fr}.user-row{grid-template-columns:42px 1fr 1fr}.user-row>*:nth-child(n+4){grid-column:auto}.user-actions{grid-column:1/-1}.user-row.header{display:none}}

</style></head><body><main class="login-shell"><section class="hero"><div class="mark">▦</div><h1>Bandwidth Command Center</h1><p>Secure access untuk monitoring trafik LibreNMS, dashboard profile, incident timeline, dan interface intelligence.</p><div class="bullet"><span>● Realtime RX / TX Monitoring</span><span>● Role-based Admin & Viewer</span><span>● Secure MySQL Authentication</span></div></section><section class="form"><h2>Login Dashboard</h2><p class="sub">Masukkan akun yang tersimpan di MySQL.</p>'.($safe!==''?'<div class="error">'.$safe.'</div>':'').'<form method="post" action="?action=login" autocomplete="on"><div class="field"><label>USERNAME</label><input name="username" autocomplete="username" required autofocus></div><div class="field"><label>PASSWORD</label><input type="password" name="password" autocomplete="current-password" required></div><button type="submit">LOGIN TO DASHBOARD</button></form><div class="foot">LibreNMS Infrastructure Monitoring</div></section></main></body></html>'; exit;
}

function jout($data, int $code=200): void { while (ob_get_level() > 0) { @ob_end_clean(); } http_response_code($code); header('Content-Type: application/json; charset=utf-8'); header('Cache-Control: no-store'); echo json_encode($data, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE); exit; }
function mbps($octets): float { return round(((float)$octets * 8) / 1000000, 3); }
function ids_param(): array { $ids=$_GET['ids']??''; if(is_array($ids))$ids=implode(',',$ids); $out=[]; foreach(explode(',',(string)$ids) as $id){$id=(int)trim($id); if($id>0)$out[$id]=$id;} return array_values($out); }
function col_exists(PDO $pdo, string $table, string $col): bool { static $c=[]; $k="$table.$col"; if(isset($c[$k]))return $c[$k]; $s=$pdo->prepare("SELECT COUNT(*) c FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND COLUMN_NAME=?"); $s->execute([$table,$col]); return $c[$k]=((int)$s->fetch()['c']>0); }
function col0(PDO $pdo, string $col, string $alias): string { return col_exists($pdo,'ports',$col) ? "COALESCE(p.`$col`,0) AS `$alias`" : "0 AS `$alias`"; }
function device_display_select(PDO $pdo): string {
    // LibreNMS versi baru dapat memiliki kolom devices.display sebagai nama tampilan override.
    // Jika kolom tidak ada, tetap aman dan menghasilkan string kosong.
    return col_exists($pdo,'devices','display')
        ? "COALESCE(NULLIF(TRIM(d.display),''),'') AS device_display"
        : "'' AS device_display";
}
function device_ip_select(PDO $pdo): string {
    // devices.ip pada LibreNMS umumnya VARBINARY. INET6_NTOA mendukung IPv4 dan IPv6.
    return col_exists($pdo,'devices','ip')
        ? "COALESCE(INET6_NTOA(d.ip),'') AS device_ip"
        : "'' AS device_ip";
}
function device_label(array $r): string {
    // Samakan dengan nama yang terlihat di UI LibreNMS: display override lebih dulu.
    // Jangan memprioritaskan sysName karena banyak FortiGate hasil template dapat memakai sysName sama.
    $display=trim((string)($r['device_display']??''));
    $host=trim((string)($r['hostname']??''));
    $sys=trim((string)($r['sysName']??''));
    if($display!=='') return $display;
    if($host!=='') return $host;
    return $sys;
}
function port_select(PDO $pdo): string {
    return "d.device_id,d.hostname,d.sysName,".device_display_select($pdo).",".device_ip_select($pdo).",p.port_id,p.ifName,p.ifDescr,p.ifAlias,p.ifSpeed,p.ifType,p.ifOperStatus,COALESCE(p.ifInOctets_rate,0) rx_rate,COALESCE(p.ifOutOctets_rate,0) tx_rate,".col0($pdo,'ifInErrors_rate','rxerr_rate').",".col0($pdo,'ifOutErrors_rate','txerr_rate').",".col0($pdo,'ifInDiscards_rate','rxdisc_rate').",".col0($pdo,'ifOutDiscards_rate','txdisc_rate');
}
function fmt_port(array $r): array {
    $label=device_label($r);
    $host=trim((string)($r['hostname']??''));
    if($host==='') $host=trim((string)($r['sysName']??''));
    $if=$r['ifName']?:$r['ifDescr'];
    $alias=$r['ifAlias']?:'';
    $speed=!empty($r['ifSpeed'])?round(((float)$r['ifSpeed'])/1000000,0):0;
    $rx=mbps($r['rx_rate']??0); $tx=mbps($r['tx_rate']??0);
    return ['port_id'=>(int)$r['port_id'],'device_id'=>(int)($r['device_id']??0),'hostname'=>$host,'sysName'=>$r['sysName']??'','device_display'=>$r['device_display']??'','device_ip'=>trim((string)($r['device_ip']??'')),'device_label'=>$label,'ifName'=>$if,'ifDescr'=>$r['ifDescr'],'ifAlias'=>$alias,'title'=>trim($label.'-'.$if.($alias?'_'.$alias:'')),'speed_mbps'=>$speed,'rx_mbps'=>$rx,'tx_mbps'=>$tx,'util_pct'=>$speed>0?round((max($rx,$tx)/$speed)*100,2):0,'status'=>$r['ifOperStatus'],'rxerr'=>round((float)($r['rxerr_rate']??0),3),'txerr'=>round((float)($r['txerr_rate']??0),3),'rxdisc'=>round((float)($r['rxdisc_rate']??0),3),'txdisc'=>round((float)($r['txdisc_rate']??0),3)];
}

function api_summary(): void { $pdo=db(); $o=['devices_total'=>0,'devices_up'=>0,'devices_down'=>0,'alerts_active'=>0,'rx_mbps'=>0,'tx_mbps'=>0,'ts'=>date('Y-m-d H:i:s')]; $o['devices_total']=(int)$pdo->query("SELECT COUNT(*) c FROM devices")->fetch()['c']; $o['devices_up']=(int)$pdo->query("SELECT COUNT(*) c FROM devices WHERE status=1")->fetch()['c']; $o['devices_down']=(int)$pdo->query("SELECT COUNT(*) c FROM devices WHERE status=0")->fetch()['c']; try{$o['alerts_active']=(int)$pdo->query("SELECT COUNT(*) c FROM alerts WHERE state IN (1,2)")->fetch()['c'];}catch(Throwable $e){} $r=$pdo->query("SELECT SUM(COALESCE(ifInOctets_rate,0))*8/1000000 rx, SUM(COALESCE(ifOutOctets_rate,0))*8/1000000 tx FROM ports WHERE ifOperStatus='up'")->fetch(); $o['rx_mbps']=round((float)($r['rx']??0),2); $o['tx_mbps']=round((float)($r['tx']??0),2); jout($o); }
function api_portlist(): void { global $EXCLUDE_IFTYPES; $pdo=db(); $q=trim((string)($_GET['q']??'')); $where='p.deleted=0'; $params=[]; if($q!==''){ $where.=" AND (d.hostname LIKE ? OR d.sysName LIKE ? OR INET6_NTOA(d.ip) LIKE ? OR p.ifName LIKE ? OR p.ifDescr LIKE ? OR p.ifAlias LIKE ?)"; $like='%'.$q.'%'; $params=[$like,$like,$like,$like,$like,$like]; } if($EXCLUDE_IFTYPES){$m=implode(',',array_fill(0,count($EXCLUDE_IFTYPES),'?')); $where.=" AND (p.ifType IS NULL OR p.ifType NOT IN ($m))"; $params=array_merge($params,$EXCLUDE_IFTYPES);} $displaySel=device_display_select($pdo); $ipSel=device_ip_select($pdo); $sql="SELECT d.device_id,d.hostname,d.sysName,$displaySel,$ipSel,p.port_id,p.ifName,p.ifDescr,p.ifAlias,p.ifSpeed,p.ifOperStatus,ROUND(COALESCE(p.ifInOctets_rate,0)*8/1000000,3) rx_mbps,ROUND(COALESCE(p.ifOutOctets_rate,0)*8/1000000,3) tx_mbps FROM ports p JOIN devices d ON d.device_id=p.device_id WHERE $where ORDER BY COALESCE(NULLIF(device_display,''),d.hostname,d.sysName),p.ifName LIMIT 1000"; $s=$pdo->prepare($sql); $s->execute($params); jout(['count'=>$s->rowCount(),'data'=>$s->fetchAll()]); }
function api_ports(): void { global $DEFAULT_PORT_IDS,$EXCLUDE_IFTYPES; $pdo=db(); $ids=ids_param(); if(!$ids && $DEFAULT_PORT_IDS)$ids=array_values(array_unique(array_map('intval',$DEFAULT_PORT_IDS))); $sel=port_select($pdo); $params=[]; if($ids){$m=implode(',',array_fill(0,count($ids),'?')); $sql="SELECT $sel FROM ports p JOIN devices d ON d.device_id=p.device_id WHERE p.deleted=0 AND p.port_id IN ($m) ORDER BY FIELD(p.port_id,$m)"; $params=array_merge($ids,$ids);} else { $where="p.deleted=0 AND p.ifOperStatus='up'"; if($EXCLUDE_IFTYPES){$m=implode(',',array_fill(0,count($EXCLUDE_IFTYPES),'?')); $where.=" AND (p.ifType IS NULL OR p.ifType NOT IN ($m))"; $params=$EXCLUDE_IFTYPES;} $sql="SELECT $sel FROM ports p JOIN devices d ON d.device_id=p.device_id WHERE $where ORDER BY (COALESCE(p.ifInOctets_rate,0)+COALESCE(p.ifOutOctets_rate,0)) DESC LIMIT ".(int)TOP_LIMIT; } $s=$pdo->prepare($sql); $s->execute($params); $out=[]; foreach($s->fetchAll() as $r)$out[]=fmt_port($r); jout(['ts'=>date('Y-m-d H:i:s'),'selected_ids'=>$ids,'data'=>$out]); }

function range_to_start(string $range): int { $map=['5m'=>300,'15m'=>900,'30m'=>1800,'1h'=>3600,'3h'=>10800,'6h'=>21600,'12h'=>43200,'1d'=>86400,'2d'=>172800,'7d'=>604800,'14d'=>1209600,'30d'=>2592000,'90d'=>7776000]; return time()-($map[$range]??21600); }
function parse_time_param($v,int $def): int { if($v===null||$v==='')return $def; if(is_numeric($v))return (int)$v; $s=str_replace('T',' ',(string)$v); $ts=strtotime($s); return $ts?$ts:$def; }
function choose_step(int $start,int $end): int { $span=max(60,$end-$start); if($span<=3600)return 60; if($span<=86400)return 300; if($span<=604800)return 900; if($span<=2592000)return 3600; return 7200; }
function rrd_paths(string $host,string $sys,int $port): array { $names=array_values(array_unique(array_filter([$host,$sys,rawurlencode($host),str_replace('/','_',$host)]))); $out=[]; foreach($names as $n)$out[]=rtrim(RRD_BASE,'/').'/'.$n.'/port-id'.$port.'.rrd'; return $out; }
function ssh_prefix(): string { $key=RRD_SSH_KEY!==''?' -i '.escapeshellarg(RRD_SSH_KEY):''; $home=RRD_SSH_HOME!==''?'HOME='.escapeshellarg(RRD_SSH_HOME).' ':''; return $home.'ssh -p '.(int)RRD_SSH_PORT.$key.' -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/var/www/.ssh/known_hosts -o IdentitiesOnly=yes '.escapeshellarg(RRD_SSH_USER.'@'.RRD_SSH_HOST).' '; }
function parse_xport(string $xmlText): array { if(!$xmlText||stripos($xmlText,'<xport')===false)return [false,[]]; $xml=@simplexml_load_string($xmlText); if(!$xml)return [false,[]]; $s=(int)$xml->meta->start; $step=(int)$xml->meta->step; $i=0; $data=[]; foreach($xml->data->row as $row){$v=$row->v; $rx=(float)$v[0]/1000000; $tx=(float)$v[1]/1000000; if(is_finite($rx)&&is_finite($tx))$data[]=['t'=>$s+($i*$step),'rx'=>round($rx,3),'tx'=>round($tx,3)]; $i++;} return [true,$data]; }
function rrd_xport_ssh(array $paths,int $start,int $end,int $step): array { $debug=[]; $debug[]='ssh_target='.RRD_SSH_USER.'@'.RRD_SSH_HOST.':'.RRD_SSH_PORT; $debug[]='ssh_key='.RRD_SSH_KEY; $basic=ssh_prefix().escapeshellarg('echo SSH_OK; whoami; hostname; id; ls -ld '.escapeshellarg(RRD_BASE).'; '.RRDTOOL_BIN.' --version | head -1').' 2>&1'; $debug[]='basic_test_output='.trim((string)shell_exec($basic)); $pid=0; foreach($paths as $p){ if(preg_match('/port-id(\d+)\.rrd$/',$p,$m)){ $pid=(int)$m[1]; break; }} $cands=$paths; if($pid>0){$find=ssh_prefix().escapeshellarg('find '.escapeshellarg(RRD_BASE).' -name '.escapeshellarg('port-id'.$pid.'.rrd').' | head -1').' 2>&1'; $found=trim((string)shell_exec($find)); $debug[]='remote_find_output='.$found; if($found!==''&&strpos($found,'.rrd')!==false&&strpos($found,'Permission denied')===false){array_unshift($cands,$found); $cands=array_values(array_unique($cands));}} foreach($cands as $rrd){$test=ssh_prefix().escapeshellarg('test -r '.escapeshellarg($rrd).' && echo OK || echo NO').' 2>&1'; $ok=trim((string)shell_exec($test)); $debug[]='path_test='.$rrd.' => '.$ok; if($ok!=='OK')continue; foreach([['INOCTETS','OUTOCTETS'],['ifInOctets','ifOutOctets']] as $ds){[$in,$out]=$ds; $remote=RRDTOOL_BIN.' xport --start '.(int)$start.' --end '.(int)$end.' --step '.(int)$step.' DEF:ino='.escapeshellarg($rrd).':'.$in.':AVERAGE DEF:out='.escapeshellarg($rrd).':'.$out.':AVERAGE CDEF:inbits=ino,8,* CDEF:outbits=out,8,* XPORT:inbits:rx XPORT:outbits:tx'; $cmd=ssh_prefix().escapeshellarg($remote).' 2>&1'; $raw=(string)shell_exec($cmd); $debug[]='xport_ds='.$in.'/'.$out; if($raw&&stripos($raw,'<xport')!==false)return [true,$raw,implode("\n",$debug)]; $debug[]='xport_raw='.substr($raw,0,800); }} return [false,'',implode("\n",$debug).'\nRRD paths tried: '.implode(', ',$cands)]; }
function api_history(): void { $pdo=db(); $port=(int)($_GET['port_id']??0); if($port<=0)jout(['error'=>'port_id wajib'],400); $range=preg_replace('/[^0-9a-z]/i','',(string)($_GET['range']??'6h')); $end=parse_time_param($_GET['to']??null,time()); $start=parse_time_param($_GET['from']??null,range_to_start($range)); if($start>=$end){$start=$end-3600;$range='1h';} $step=choose_step($start,$end); $s=$pdo->prepare("SELECT d.hostname,d.sysName,p.port_id,p.ifName,p.ifDescr,p.ifAlias,p.ifSpeed,COALESCE(p.ifInOctets_rate,0) rx_rate,COALESCE(p.ifOutOctets_rate,0) tx_rate FROM ports p JOIN devices d ON d.device_id=p.device_id WHERE p.port_id=? LIMIT 1"); $s->execute([$port]); $p=$s->fetch(); if(!$p)jout(['error'=>'port tidak ketemu'],404); $host=$p['hostname']?:$p['sysName']; $paths=rrd_paths($host,$p['sysName']?:'', $port); [$ok,$raw,$debug]=rrd_xport_ssh($paths,$start,$end,$step); [$parsed,$data]=parse_xport($raw); if($ok&&$parsed)jout(['source'=>'rrd-ssh','range'=>$range,'from'=>$start,'to'=>$end,'step'=>$step,'data'=>$data]); jout(['source'=>'live-db-fallback','range'=>$range,'from'=>$start,'to'=>$end,'step'=>$step,'warning'=>'History RRD belum bisa dibaca. Lihat debug.','debug'=>$debug,'paths'=>$paths,'data'=>[['t'=>time(),'rx'=>mbps($p['rx_rate']),'tx'=>mbps($p['tx_rate'])]]]); }
function api_diag(): void { $out=['history_method'=>HISTORY_METHOD,'ssh_target'=>RRD_SSH_USER.'@'.RRD_SSH_HOST.':'.RRD_SSH_PORT,'ssh_key'=>RRD_SSH_KEY,'ssh_home'=>RRD_SSH_HOME,'shell_exec_enabled'=>function_exists('shell_exec')]; if(function_exists('shell_exec')){$out['whoami']=trim((string)shell_exec('whoami 2>&1')); $out['ssh_test']=trim((string)shell_exec(ssh_prefix().escapeshellarg('echo OK; whoami; find /opt/librenms/rrd -name "port-id*.rrd" | head -3').' 2>&1'));} jout($out); }


function saved_ports_file(): string { return __DIR__ . '/dashboard_ports.json'; }
function api_load_ports_saved(): void {
    $f = saved_ports_file();
    if (!is_readable($f)) jout(['ports'=>[],'file'=>$f]);
    $raw = (string)file_get_contents($f);
    $j = json_decode($raw, true);
    // Kalau file pernah corrupt karena output nyasar, coba ambil JSON object di dalamnya.
    if (!is_array($j)) {
        $a = strpos($raw, '{'); $b = strrpos($raw, '}');
        if ($a !== false && $b !== false && $b > $a) $j = json_decode(substr($raw, $a, $b-$a+1), true);
    }
    $ports = [];
    if (is_array($j) && isset($j['ports']) && is_array($j['ports'])) {
        foreach ($j['ports'] as $id) { $id=(int)$id; if($id>0)$ports[$id]=$id; }
    }
    // Rewrite bersih supaya error token aneh tidak muncul lagi.
    @file_put_contents($f, json_encode(['ports'=>array_values($ports),'updated_at'=>date('Y-m-d H:i:s')], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
    @chmod($f, 0664);
    jout(['ports'=>array_values($ports),'file'=>$f]);
}
function api_save_ports_selected(): void {
    $raw = file_get_contents('php://input');
    $j = json_decode((string)$raw, true);
    $ports = [];
    if (is_array($j) && isset($j['ports']) && is_array($j['ports'])) {
        foreach ($j['ports'] as $id) { $id=(int)$id; if($id>0)$ports[$id]=$id; }
    }
    $data = ['ports'=>array_values($ports),'updated_at'=>date('Y-m-d H:i:s')];
    $ok = @file_put_contents(saved_ports_file(), json_encode($data, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES), LOCK_EX);
    if ($ok === false) jout(['ok'=>false,'error'=>'Gagal write '.saved_ports_file().'. Pastikan folder dashboard writable oleh user webserver.'],500);
    @chmod(saved_ports_file(), 0664);
    jout(['ok'=>true,'ports'=>$data['ports'],'file'=>saved_ports_file(),'count'=>count($data['ports'])]);
}


function profiles_file(): string { return __DIR__ . '/dashboard_profiles.json'; }
function read_profiles_data(): array {
    $f = profiles_file();
    if (!is_readable($f)) return ['profiles'=>[], 'last_profile'=>''];
    $raw = (string)file_get_contents($f);
    $j = json_decode($raw, true);
    if (!is_array($j)) {
        $a=strpos($raw,'{'); $b=strrpos($raw,'}');
        if($a!==false && $b!==false && $b>$a) $j=json_decode(substr($raw,$a,$b-$a+1), true);
    }
    if (!is_array($j)) $j=[];
    if (!isset($j['profiles']) || !is_array($j['profiles'])) $j['profiles']=[];
    if (!isset($j['last_profile'])) $j['last_profile']='';
    $clean=[];
    foreach($j['profiles'] as $name=>$ports){
        $name=trim((string)$name); if($name==='') continue;
        $ids=[]; if(is_array($ports)) foreach($ports as $id){$id=(int)$id; if($id>0)$ids[$id]=$id;}
        $clean[$name]=array_values($ids);
    }
    $j['profiles']=$clean;
    return $j;
}
function render_profile_options_server(): string {
    $d=read_profiles_data();
    $profiles=$d['profiles'] ?? [];
    $last=(string)($d['last_profile'] ?? '');
    $html=auth_is_admin()
        ? '<option value="__new__">+ New Dashboard / Kosong</option>'
        : '<option value="">Pilih dashboard untuk dilihat...</option>';
    foreach($profiles as $name=>$ids){
        $name=(string)$name;
        $count=is_array($ids)?count($ids):0;
        $selected=$name===$last?' selected':'';
        $json=htmlspecialchars(json_encode(array_values(array_map('intval',(array)$ids))),ENT_QUOTES,'UTF-8');
        $html.='<option value="'.htmlspecialchars($name,ENT_QUOTES,'UTF-8').'" data-ids="'.$json.'"'.$selected.'>'.htmlspecialchars($name,ENT_QUOTES,'UTF-8').' ('.$count.' port)</option>';
    }
    return $html;
}
function write_profiles_data(array $data): bool {
    if (!isset($data['profiles']) || !is_array($data['profiles'])) $data['profiles']=[];
    if (!isset($data['last_profile'])) $data['last_profile']='';
    $data['updated_at']=date('Y-m-d H:i:s');
    $ok=@file_put_contents(profiles_file(), json_encode($data, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES), LOCK_EX);
    if($ok!==false) @chmod(profiles_file(),0664);
    return $ok!==false;
}
function api_profiles_load(): void { $d=read_profiles_data(); jout(['profiles'=>$d['profiles'],'last_profile'=>$d['last_profile'],'file'=>profiles_file()]); }
function api_profiles_save(): void {
    $raw=file_get_contents('php://input'); $j=json_decode((string)$raw,true);
    $name=trim((string)($j['name']??'')); if($name==='') jout(['ok'=>false,'error'=>'Nama dashboard wajib diisi'],400);
    $name=preg_replace('/[^A-Za-z0-9 _\-.]/','_', $name);
    $ports=[]; if(isset($j['ports']) && is_array($j['ports'])) foreach($j['ports'] as $id){$id=(int)$id; if($id>0)$ports[$id]=$id;}
    $d=read_profiles_data(); $d['profiles'][$name]=array_values($ports); $d['last_profile']=$name;
    if(!write_profiles_data($d)) jout(['ok'=>false,'error'=>'Gagal write '.profiles_file().'. Pastikan file/folder writable oleh apache.'],500);
    // juga sync ke dashboard_ports.json sebagai fallback
    @file_put_contents(saved_ports_file(), json_encode(['ports'=>array_values($ports),'updated_at'=>date('Y-m-d H:i:s')], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES), LOCK_EX);
    @chmod(saved_ports_file(),0664);
    jout(['ok'=>true,'name'=>$name,'ports'=>array_values($ports),'profiles'=>$d['profiles'],'file'=>profiles_file()]);
}
function api_profiles_delete(): void {
    $raw=file_get_contents('php://input'); $j=json_decode((string)$raw,true);
    $name=trim((string)($j['name']??'')); if($name==='') jout(['ok'=>false,'error'=>'Nama dashboard wajib diisi'],400);
    $d=read_profiles_data(); unset($d['profiles'][$name]); if(($d['last_profile']??'')===$name)$d['last_profile']='';
    if(!write_profiles_data($d)) jout(['ok'=>false,'error'=>'Gagal update '.profiles_file()],500);
    jout(['ok'=>true,'profiles'=>$d['profiles']]);
}
function api_groups(): void { global $GROUPS; jout(['groups'=>$GROUPS]); }
function percentile(array $arr, float $p): float {
    $arr = array_values(array_filter(array_map('floatval',$arr), fn($v)=>is_finite($v)));
    if (!$arr) return 0.0; sort($arr); $idx = ($p/100) * (count($arr)-1); $lo=floor($idx); $hi=ceil($idx);
    if ($lo == $hi) return round($arr[$lo],3); return round($arr[$lo] + ($arr[$hi]-$arr[$lo])*($idx-$lo),3);
}
function api_top_traffic(): void {
    global $EXCLUDE_IFTYPES; $pdo=db(); $sel=port_select($pdo); $where="p.deleted=0 AND p.ifOperStatus='up'"; $params=[];
    if($EXCLUDE_IFTYPES){$m=implode(',',array_fill(0,count($EXCLUDE_IFTYPES),'?')); $where.=" AND (p.ifType IS NULL OR p.ifType NOT IN ($m))"; $params=$EXCLUDE_IFTYPES;}
    $sql="SELECT $sel FROM ports p JOIN devices d ON d.device_id=p.device_id WHERE $where ORDER BY (COALESCE(p.ifInOctets_rate,0)+COALESCE(p.ifOutOctets_rate,0)) DESC LIMIT 50";
    $s=$pdo->prepare($sql); $s->execute($params); $rows=[]; foreach($s->fetchAll() as $r)$rows[]=fmt_port($r);
    $rx=$rows; usort($rx,fn($a,$b)=>$b['rx_mbps']<=>$a['rx_mbps']);
    $tx=$rows; usort($tx,fn($a,$b)=>$b['tx_mbps']<=>$a['tx_mbps']);
    $util=$rows; usort($util,fn($a,$b)=>$b['util_pct']<=>$a['util_pct']);
    jout(['rx'=>array_slice($rx,0,10),'tx'=>array_slice($tx,0,10),'util'=>array_slice($util,0,10),'ts'=>date('Y-m-d H:i:s')]);
}
function api_export_report(): void {
    $pdo=db(); $ids=ids_param(); if(!$ids) jout(['error'=>'ids kosong'],400);
    $range=preg_replace('/[^0-9a-z]/i','',(string)($_GET['range']??'6h'));
    $end=parse_time_param($_GET['to']??null,time()); $start=parse_time_param($_GET['from']??null,range_to_start($range)); if($start>=$end)$start=$end-3600; $step=choose_step($start,$end);
    header('Content-Type: text/csv; charset=utf-8'); header('Content-Disposition: attachment; filename="bandwidth_report_'.date('Ymd_His').'.csv"');
    $out=fopen('php://output','w'); fputcsv($out,['port_id','device','interface','alias','from','to','avg_rx_mbps','avg_tx_mbps','max_rx_mbps','max_tx_mbps','p95_rx_mbps','p95_tx_mbps']);
    foreach($ids as $port){
        $s=$pdo->prepare("SELECT d.hostname,d.sysName,p.port_id,p.ifName,p.ifDescr,p.ifAlias,p.ifSpeed,COALESCE(p.ifInOctets_rate,0) rx_rate,COALESCE(p.ifOutOctets_rate,0) tx_rate FROM ports p JOIN devices d ON d.device_id=p.device_id WHERE p.port_id=? LIMIT 1"); $s->execute([$port]); $p=$s->fetch(); if(!$p)continue;
        $host=$p['hostname']?:$p['sysName']; $paths=rrd_paths($host,$p['sysName']?:'', $port); [$ok,$raw,$debug]=rrd_xport_ssh($paths,$start,$end,$step); [$parsed,$data]=parse_xport($raw);
        $rx=[]; $tx=[]; foreach($data as $d){$rx[]=(float)$d['rx']; $tx[]=(float)$d['tx'];}
        $avgRx=$rx?round(array_sum($rx)/count($rx),3):0; $avgTx=$tx?round(array_sum($tx)/count($tx),3):0; $maxRx=$rx?round(max($rx),3):0; $maxTx=$tx?round(max($tx),3):0;
        fputcsv($out,[$port,device_label($p),$p['ifName']?:$p['ifDescr'],$p['ifAlias'],date('Y-m-d H:i:s',$start),date('Y-m-d H:i:s',$end),$avgRx,$avgTx,$maxRx,$maxTx,percentile($rx,95),percentile($tx,95)]);
    }
    fclose($out); exit;
}
function api_users_list(): void {
    auth_require_admin();
    $rows=auth_db()->query("SELECT id,username,full_name,role,is_active,last_login,created_at,updated_at FROM dashboard_users ORDER BY role,username")->fetchAll();
    jout(['ok'=>true,'users'=>$rows]);
}
function api_users_create(): void {
    auth_require_admin(); auth_check_csrf();
    $j=json_decode((string)file_get_contents('php://input'),true) ?: [];
    $username=strtolower(trim((string)($j['username']??'')));
    $fullName=trim((string)($j['full_name']??''));
    $password=(string)($j['password']??'');
    $role=(string)($j['role']??'viewer');
    if(!preg_match('/^[a-z0-9._-]{3,50}$/',$username)) jout(['error'=>'Username minimal 3 karakter: huruf kecil, angka, titik, garis bawah, atau minus.'],422);
    if(strlen($password)<8) jout(['error'=>'Password minimal 8 karakter.'],422);
    if(!in_array($role,['admin','viewer'],true)) $role='viewer';
    if($fullName==='') $fullName=$username;
    try {
        $st=auth_db()->prepare("INSERT INTO dashboard_users(username,password_hash,full_name,role,is_active,created_by) VALUES(?,?,?,?,1,?)");
        $st->execute([$username,password_hash($password,PASSWORD_DEFAULT),$fullName,$role,(int)auth_user()['id']]);
        jout(['ok'=>true,'message'=>'User berhasil dibuat.','id'=>(int)auth_db()->lastInsertId()]);
    } catch(PDOException $e){ if((string)$e->getCode()==='23000') jout(['error'=>'Username sudah digunakan.'],409); throw $e; }
}
function api_users_update(): void {
    auth_require_admin(); auth_check_csrf();
    $j=json_decode((string)file_get_contents('php://input'),true) ?: [];
    $id=(int)($j['id']??0); if($id<=0) jout(['error'=>'User tidak valid.'],422);
    $st=auth_db()->prepare("SELECT id,username,role,is_active FROM dashboard_users WHERE id=?");$st->execute([$id]);$target=$st->fetch();if(!$target)jout(['error'=>'User tidak ditemukan.'],404);
    $fullName=trim((string)($j['full_name']??''));$role=(string)($j['role']??$target['role']);$active=!empty($j['is_active'])?1:0;
    if(!in_array($role,['admin','viewer'],true)) jout(['error'=>'Role tidak valid.'],422);
    if($id===(int)auth_user()['id'] && ($active===0 || $role!=='admin')) jout(['error'=>'Admin yang sedang login tidak boleh menonaktifkan atau menurunkan role akun sendiri.'],422);
    if($target['role']==='admin' && ($role!=='admin'||$active===0)){
        $count=(int)auth_db()->query("SELECT COUNT(*) FROM dashboard_users WHERE role='admin' AND is_active=1")->fetchColumn();
        if($count<=1) jout(['error'=>'Minimal harus ada satu Admin aktif.'],422);
    }
    auth_db()->prepare("UPDATE dashboard_users SET full_name=?,role=?,is_active=? WHERE id=?")->execute([$fullName?:$target['username'],$role,$active,$id]);
    jout(['ok'=>true,'message'=>'User berhasil diperbarui.']);
}
function api_users_reset_password(): void {
    auth_require_admin(); auth_check_csrf();
    $j=json_decode((string)file_get_contents('php://input'),true) ?: [];$id=(int)($j['id']??0);$password=(string)($j['password']??'');
    if($id<=0||strlen($password)<8) jout(['error'=>'Password baru minimal 8 karakter.'],422);
    $st=auth_db()->prepare("UPDATE dashboard_users SET password_hash=? WHERE id=?");$st->execute([password_hash($password,PASSWORD_DEFAULT),$id]);
    if(!$st->rowCount()) jout(['error'=>'User tidak ditemukan.'],404); jout(['ok'=>true,'message'=>'Password berhasil direset.']);
}
function api_users_delete(): void {
    auth_require_admin(); auth_check_csrf();
    $j=json_decode((string)file_get_contents('php://input'),true) ?: [];$id=(int)($j['id']??0);
    if($id===(int)auth_user()['id']) jout(['error'=>'Akun yang sedang login tidak dapat dihapus.'],422);
    $st=auth_db()->prepare("SELECT role,is_active FROM dashboard_users WHERE id=?");$st->execute([$id]);$target=$st->fetch();if(!$target)jout(['error'=>'User tidak ditemukan.'],404);
    if($target['role']==='admin'&&(int)$target['is_active']===1){$count=(int)auth_db()->query("SELECT COUNT(*) FROM dashboard_users WHERE role='admin' AND is_active=1")->fetchColumn();if($count<=1)jout(['error'=>'Admin aktif terakhir tidak dapat dihapus.'],422);}
    auth_db()->prepare("DELETE FROM dashboard_users WHERE id=?")->execute([$id]);jout(['ok'=>true,'message'=>'User berhasil dihapus.']);
}

if (($_GET['page'] ?? '') === 'auth_health') {
    header('Content-Type: application/json; charset=utf-8');
    try {
        $pdo=auth_db();
        $table=(string)$pdo->query("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='dashboard_users'")->fetchColumn();
        $users=$table==='1' ? (int)$pdo->query("SELECT COUNT(*) FROM dashboard_users")->fetchColumn() : 0;
        echo json_encode(['ok'=>true,'database'=>AUTH_DB_NAME,'table_dashboard_users'=>$table==='1','users'=>$users],JSON_UNESCAPED_SLASHES); exit;
    } catch(Throwable $e) {
        http_response_code(500);
        echo json_encode(['ok'=>false,'error'=>$e->getMessage()],JSON_UNESCAPED_SLASHES); exit;
    }
}
if (($_GET['action'] ?? '') === 'login' && $_SERVER['REQUEST_METHOD']==='POST') auth_login_attempt();
if (($_GET['action'] ?? '') === 'logout') auth_logout();
if (($_GET['page'] ?? '') === 'login') render_login_page();

if(isset($_GET['api'])){ try{ auth_require_login(true); if($_GET['api']==='users_list')api_users_list(); if($_GET['api']==='users_create')api_users_create(); if($_GET['api']==='users_update')api_users_update(); if($_GET['api']==='users_reset_password')api_users_reset_password(); if($_GET['api']==='users_delete')api_users_delete(); if(in_array((string)($_GET['api']??''),['profiles_save','profiles_delete','save_ports'],true)){auth_require_admin();auth_check_csrf();} if($_GET['api']==='summary')api_summary(); if($_GET['api']==='portlist')api_portlist(); if($_GET['api']==='ports')api_ports(); if($_GET['api']==='history')api_history(); if($_GET['api']==='diag')api_diag(); if($_GET['api']==='profiles_load')api_profiles_load(); if($_GET['api']==='profiles_save')api_profiles_save(); if($_GET['api']==='profiles_delete')api_profiles_delete(); if($_GET['api']==='groups')api_groups(); if($_GET['api']==='top_traffic')api_top_traffic(); if($_GET['api']==='export_report')api_export_report(); if($_GET['api']==='load_ports')api_load_ports_saved(); if($_GET['api']==='save_ports')api_save_ports_selected(); jout(['error'=>'Invalid API'],404);}catch(Throwable $e){jout(['error'=>$e->getMessage()],500);} }

// Dashboard HTML hanya boleh dirender setelah session login valid.
auth_require_login(false);
?>
<!doctype html><html lang="id"><head><style id="user-management-v55">
/* V59 CLEAN VIEWER TOOLBAR */
.user-modal{display:none!important;position:fixed!important;inset:0!important;z-index:2147483000!important;padding:24px!important;background:rgba(2,12,20,.82)!important;backdrop-filter:blur(10px)!important}
.user-modal.open{display:flex!important;align-items:center!important;justify-content:center!important}
.user-dialog{position:relative!important;width:min(1050px,96vw)!important;max-height:90vh!important;margin:0!important;display:flex!important;flex-direction:column!important;overflow:hidden!important;border:1px solid #55a9cc!important;border-radius:20px!important;background:#f4f8fb!important;box-shadow:0 35px 100px rgba(0,0,0,.58)!important}
.user-dialog-head{display:flex!important;align-items:center!important;justify-content:space-between!important;min-height:76px!important;padding:15px 20px!important;color:#fff!important;background:linear-gradient(120deg,#082b3e,#087788 54%,#3269d4)!important}
.user-dialog-head small{display:block!important;color:#a9e9f4!important;font:900 8px Arial!important;letter-spacing:1.4px!important}
.user-dialog-head h2{margin:4px 0 0!important;color:#fff!important;font:800 20px Arial!important}
.user-dialog-head button{width:36px!important;min-width:36px!important;height:36px!important;margin:0!important;padding:0!important;border:1px solid rgba(255,255,255,.32)!important;border-radius:10px!important;color:#fff!important;background:rgba(255,255,255,.12)!important;box-shadow:none!important;font:400 21px Arial!important;cursor:pointer!important}
.user-create{display:grid!important;grid-template-columns:1fr 1.35fr 1fr 110px 125px!important;gap:9px!important;padding:15px 16px!important;border-bottom:1px solid #d1e1e9!important;background:linear-gradient(180deg,#edf6fa,#e4eff4)!important}
.user-create input,.user-create select{display:block!important;width:100%!important;height:40px!important;margin:0!important;padding:0 11px!important;border:1px solid #b9d0dc!important;border-radius:9px!important;color:#25485a!important;background:#fff!important;font:12px Arial!important;outline:0!important}
.user-create input:focus,.user-create select:focus{border-color:#278acb!important;box-shadow:0 0 0 3px rgba(39,138,203,.14)!important}
.user-create button{width:125px!important;min-width:125px!important;height:40px!important;margin:0!important;padding:0 12px!important;border:0!important;border-radius:9px!important;color:#fff!important;background:linear-gradient(135deg,#087ca8,#326fd3)!important;box-shadow:0 7px 16px rgba(24,105,167,.23)!important;font:900 10px Arial!important;cursor:pointer!important}
.user-list{min-height:170px!important;padding:13px!important;overflow:auto!important;background:#f7fafc!important}
.user-row{display:grid!important;grid-template-columns:42px minmax(110px,1fr) minmax(150px,1.35fr) 95px 110px 145px 218px!important;gap:8px!important;align-items:center!important;margin:0 0 7px!important;padding:8px 9px!important;border:1px solid #d6e4ea!important;border-radius:11px!important;background:#fff!important;box-shadow:0 3px 10px rgba(35,75,96,.05)!important}
.user-row.header{position:sticky!important;top:-13px!important;z-index:2!important;padding-top:10px!important;padding-bottom:10px!important;color:#627b88!important;background:#eaf2f6!important;font:900 8px Arial!important;letter-spacing:.5px!important}
.user-row b{color:#294b5d!important;font:800 11px Arial!important}.user-row>span{overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important;color:#315467!important;font:11px Arial!important}
.user-row input,.user-row select{width:100%!important;height:34px!important;margin:0!important;padding:0 8px!important;border:1px solid #c5d9e3!important;border-radius:8px!important;color:#294b5d!important;background:#fbfdfe!important;font:11px Arial!important}
.user-status{display:flex!important;align-items:center!important;gap:5px!important;color:#07845f!important;font:900 8px Arial!important;white-space:nowrap!important}.user-status.off{color:#c0392b!important}.user-status input{width:15px!important;height:15px!important;margin:0!important}.user-row small{color:#778e9a!important;font:9px Arial!important;white-space:nowrap!important}
.user-actions{display:flex!important;gap:5px!important;justify-content:flex-end!important}.user-actions button{width:auto!important;min-width:0!important;height:30px!important;margin:0!important;padding:0 8px!important;border:1px solid #bdd3de!important;border-radius:7px!important;color:#315d73!important;background:#edf6fa!important;box-shadow:none!important;font:900 8px Arial!important;white-space:nowrap!important;cursor:pointer!important}.user-actions .danger{border-color:#d65665!important;color:#fff!important;background:#d94b5a!important}
.user-message{min-height:40px!important;padding:11px 16px!important;border-top:1px solid #d5e3e9!important;color:#607985!important;background:#edf4f7!important;font:700 10px Arial!important}.user-message.error{color:#a72839!important;background:#fff0f2!important}
.user-session{display:flex!important;align-items:center!important;gap:8px!important;min-width:0!important;padding:6px 7px 6px 11px!important;border:1px solid rgba(255,255,255,.18)!important;border-radius:13px!important;background:rgba(255,255,255,.08)!important}
.user-session strong{display:block!important;max-width:165px!important;overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important;color:#f2fbff!important;font:800 11px Arial!important}
.role-pill{display:inline-flex!important;align-items:center!important;justify-content:center!important;height:24px!important;padding:0 9px!important;border:1px solid rgba(95,203,255,.35)!important;border-radius:999px!important;color:#dff8ff!important;background:rgba(34,139,230,.28)!important;font:900 8px Arial!important;letter-spacing:.7px!important}
.user-manage-btn{display:inline-flex!important;align-items:center!important;justify-content:center!important;width:76px!important;min-width:76px!important;height:31px!important;margin:0!important;padding:0 12px!important;border:1px solid rgba(119,218,255,.42)!important;border-radius:9px!important;color:#fff!important;background:linear-gradient(135deg,#087fa8,#3578df)!important;box-shadow:0 6px 15px rgba(7,92,145,.27)!important;font:900 10px Arial!important;cursor:pointer!important}
.logout-link{display:inline-flex!important;align-items:center!important;justify-content:center!important;height:31px!important;padding:0 11px!important;border:1px solid rgba(255,144,157,.35)!important;border-radius:9px!important;color:#fff!important;text-decoration:none!important;background:rgba(215,65,83,.8)!important;font:900 9px Arial!important}
.viewer-notice{display:none!important}body.role-viewer .viewer-notice{display:block!important;margin:9px 12px 0!important;padding:9px 12px!important;border:1px solid #f0d18d!important;border-radius:10px!important;color:#825400!important;background:#fff7e6!important;font-weight:700!important}body.role-viewer .admin-only{display:none!important}
@media(max-width:1000px){.user-create{grid-template-columns:1fr 1fr!important}.user-create button{width:100%!important}.user-row{grid-template-columns:40px 1fr 1.2fr!important}.user-row.header{display:none!important}.user-actions{grid-column:1/-1!important;justify-content:flex-start!important}}
@media(max-width:650px){.user-modal{padding:8px!important}.user-dialog{max-height:96vh!important;border-radius:14px!important}.user-create{grid-template-columns:1fr!important}.user-row{grid-template-columns:34px 1fr!important}.user-row>*:nth-child(n+3){grid-column:1/-1!important}.user-actions{flex-wrap:wrap!important}.user-session strong{max-width:110px!important}}

.dashboard-profile-row{position:relative!important;display:flex!important;align-items:center!important;gap:9px!important;padding:9px!important;border:1px solid #c8e1ee!important;border-radius:12px!important;background:linear-gradient(120deg,rgba(234,247,253,.95),rgba(242,248,255,.95))!important}
.viewer-dashboard-label{display:inline-flex;align-items:center;height:34px;padding:0 10px;border-radius:8px;color:#17658a;background:#dff2fa;font:900 9px Arial;letter-spacing:.65px;white-space:nowrap}
.dashboard-profile-row #profileSelect{min-width:250px!important;max-width:420px!important;flex:1 1 280px!important;border-color:#9fcddd!important;background:#fff!important;font-weight:800!important}
body.role-viewer .dashboard-profile-row{margin-top:2px!important;border-color:#b9d9e5!important;background:linear-gradient(120deg,#edf8fc,#f5f8ff)!important}
body.role-viewer .dashboard-profile-row:after{content:"View only • data dari dashboard_profiles.json";color:#6f8793;font:700 9px Arial;margin-left:auto;white-space:nowrap}
body.dark .dashboard-profile-row,body.theme-noc .dashboard-profile-row{border-color:#315565!important;background:linear-gradient(120deg,#102b37,#171f3b)!important}body.dark .viewer-dashboard-label,body.theme-noc .viewer-dashboard-label{color:#9ce9f9;background:#173d4d}body.dark .dashboard-profile-row #profileSelect,body.theme-noc .dashboard-profile-row #profileSelect{border-color:#315565!important;color:#dff3fa!important;background:#102733!important}
@media(max-width:760px){.dashboard-profile-row{align-items:stretch!important;flex-direction:column!important}.viewer-dashboard-label{justify-content:center}.dashboard-profile-row #profileSelect{width:100%!important;max-width:none!important}.dashboard-profile-row:after{margin:0!important;text-align:center}}

/* V59 CLEAN VIEWER TOOLBAR */
body.role-viewer .viewer-hidden-control{display:none!important}
body.role-viewer .toolbar-row.actions{display:none!important}
body.role-viewer .dashboard-profile-row{margin-bottom:0!important}
body.role-viewer .dashboard-profile-row:after{content:"Dashboard aktif: " attr(data-active-profile);display:none}
body.role-viewer .toolbar{padding:9px!important}
body.role-viewer .viewer-dashboard-label{min-width:118px!important;justify-content:center!important}
body.role-viewer #profileSelect{max-width:460px!important}

.viewer-profile-status{display:none;color:#637b88;font:700 10px Arial;white-space:nowrap}
body.role-viewer .viewer-profile-status{display:inline-flex;align-items:center;margin-left:4px}
@media(max-width:760px){body.role-viewer .viewer-profile-status{justify-content:center;margin:0;white-space:normal;text-align:center}}
</style>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>LibreNMS Bandwidth Dashboard</title><meta name="ui-build" content="v59-viewer-clean-toolbar"><link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2064%2064%22%3E%3Cdefs%3E%3ClinearGradient%20id%3D%22b%22%20x1%3D%220%22%20y1%3D%220%22%20x2%3D%221%22%20y2%3D%221%22%3E%3Cstop%20stop-color%3D%22%23071827%22%2F%3E%3Cstop%20offset%3D%221%22%20stop-color%3D%22%23075b78%22%2F%3E%3C%2FlinearGradient%3E%3C%2Fdefs%3E%3Crect%20width%3D%2264%22%20height%3D%2264%22%20rx%3D%2215%22%20fill%3D%22url%28%23b%29%22%2F%3E%3Crect%20x%3D%2213%22%20y%3D%2210%22%20width%3D%2238%22%20height%3D%2244%22%20rx%3D%227%22%20fill%3D%22%230d2636%22%20stroke%3D%22%2376eaff%22%20stroke-width%3D%223%22%2F%3E%3Cg%20fill%3D%22%23153d50%22%20stroke-width%3D%222%22%3E%3Crect%20x%3D%2218%22%20y%3D%2216%22%20width%3D%2228%22%20height%3D%228%22%20rx%3D%222%22%20stroke%3D%22%2300d6a3%22%2F%3E%3Crect%20x%3D%2218%22%20y%3D%2228%22%20width%3D%2228%22%20height%3D%228%22%20rx%3D%222%22%20stroke%3D%22%23887cff%22%2F%3E%3Crect%20x%3D%2218%22%20y%3D%2240%22%20width%3D%2228%22%20height%3D%228%22%20rx%3D%222%22%20stroke%3D%22%2326bde3%22%2F%3E%3C%2Fg%3E%3Cg%3E%3Ccircle%20cx%3D%2223%22%20cy%3D%2220%22%20r%3D%222%22%20fill%3D%22%2300e5ad%22%2F%3E%3Ccircle%20cx%3D%2223%22%20cy%3D%2232%22%20r%3D%222%22%20fill%3D%22%23958cff%22%2F%3E%3Ccircle%20cx%3D%2223%22%20cy%3D%2244%22%20r%3D%222%22%20fill%3D%22%2331cff2%22%2F%3E%3C%2Fg%3E%3Cpath%20d%3D%22M29%2020h11M29%2032h11M29%2044h11%22%20stroke%3D%22%23d9f8ff%22%20stroke-width%3D%222%22%20stroke-linecap%3D%22round%22%2F%3E%3C%2Fsvg%3E"><link rel="shortcut icon" href="data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2064%2064%22%3E%3Cdefs%3E%3ClinearGradient%20id%3D%22b%22%20x1%3D%220%22%20y1%3D%220%22%20x2%3D%221%22%20y2%3D%221%22%3E%3Cstop%20stop-color%3D%22%23071827%22%2F%3E%3Cstop%20offset%3D%221%22%20stop-color%3D%22%23075b78%22%2F%3E%3C%2FlinearGradient%3E%3C%2Fdefs%3E%3Crect%20width%3D%2264%22%20height%3D%2264%22%20rx%3D%2215%22%20fill%3D%22url%28%23b%29%22%2F%3E%3Crect%20x%3D%2213%22%20y%3D%2210%22%20width%3D%2238%22%20height%3D%2244%22%20rx%3D%227%22%20fill%3D%22%230d2636%22%20stroke%3D%22%2376eaff%22%20stroke-width%3D%223%22%2F%3E%3Cg%20fill%3D%22%23153d50%22%20stroke-width%3D%222%22%3E%3Crect%20x%3D%2218%22%20y%3D%2216%22%20width%3D%2228%22%20height%3D%228%22%20rx%3D%222%22%20stroke%3D%22%2300d6a3%22%2F%3E%3Crect%20x%3D%2218%22%20y%3D%2228%22%20width%3D%2228%22%20height%3D%228%22%20rx%3D%222%22%20stroke%3D%22%23887cff%22%2F%3E%3Crect%20x%3D%2218%22%20y%3D%2240%22%20width%3D%2228%22%20height%3D%228%22%20rx%3D%222%22%20stroke%3D%22%2326bde3%22%2F%3E%3C%2Fg%3E%3Cg%3E%3Ccircle%20cx%3D%2223%22%20cy%3D%2220%22%20r%3D%222%22%20fill%3D%22%2300e5ad%22%2F%3E%3Ccircle%20cx%3D%2223%22%20cy%3D%2232%22%20r%3D%222%22%20fill%3D%22%23958cff%22%2F%3E%3Ccircle%20cx%3D%2223%22%20cy%3D%2244%22%20r%3D%222%22%20fill%3D%22%2331cff2%22%2F%3E%3C%2Fg%3E%3Cpath%20d%3D%22M29%2020h11M29%2032h11M29%2044h11%22%20stroke%3D%22%23d9f8ff%22%20stroke-width%3D%222%22%20stroke-linecap%3D%22round%22%2F%3E%3C%2Fsvg%3E"><meta name="theme-color" content="#071827"><style>
*{box-sizing:border-box}body{margin:0;background:#e9edf1;color:#1d2b36;font-family:Arial,Helvetica,sans-serif;font-size:12px}.topbar{background:#263845;color:#fff;display:flex;justify-content:space-between;align-items:center;padding:8px 14px;border-bottom:3px solid #1a2730}.topbar h1{font-size:20px;margin:0 0 3px}.topbar p{margin:0;color:#b8c7d1}.clock{font-weight:bold;font-size:16px}.summary{display:grid;grid-template-columns:repeat(6,1fr);gap:8px;padding:8px}.kpi{background:#fff;border:1px solid #d4dce2;padding:10px 12px;border-left:5px solid #6b7c86}.kpi b{font-size:22px;display:block}.good{border-left-color:#2ecc71}.bad{border-left-color:#e74c3c}.warn{border-left-color:#f39c12}.blue{border-left-color:#3498db}.purple{border-left-color:#9b59b6}.toolbar{margin:0 8px 10px;background:linear-gradient(180deg,#ffffff,#f7fafc);border:1px solid #cfd8df;padding:10px;border-radius:6px;display:flex;flex-direction:column;gap:8px;box-shadow:0 2px 8px rgba(38,56,69,.06)}.toolbar-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.toolbar-row.main-search{display:grid;grid-template-columns:260px 1fr 130px;gap:8px}.toolbar input,.toolbar select,.toolbar button{height:34px;border:1px solid #b8c4cc;border-radius:4px;padding:5px 10px;font-size:13px}.toolbar button{background:#0073aa;color:#fff;border-color:#005f8d;cursor:pointer;font-weight:700;white-space:nowrap;min-width:86px}.toolbar button:hover{filter:brightness(1.08)}#saveBtn{min-width:145px;background:#0b78b6}#exportBtn{min-width:108px}#exportDocBtn{min-width:150px;background:#2c7be5!important;border-color:#1f5fb4!important}#exportChartBtn{min-width:170px;background:#16a085!important;border-color:#0f766e!important}#resetBtn{min-width:126px}#clearBtn{min-width:70px}#themeSelect{min-width:150px}#profileSelect{min-width:220px}#profileName{min-width:280px;flex:1}.toolbar-row.profiles{background:rgba(232,244,251,.65);border:1px dashed #b7cedb;border-radius:6px;padding:7px}.btn-danger{background:#c0392b!important;border-color:#922b21!important}#newDashboardBtn{background:#607d8b!important;border-color:#455a64!important}.save-status{font-size:12px;color:#60727f;min-width:110px}.range,.custom-time,.chips{width:100%}.range button{height:26px;margin:2px 4px 2px 0;background:#eef4f8;color:#315367;border:1px solid #b8c4cc}.range button.active{background:#607d8b;color:#fff}.custom-time{display:flex;gap:6px;align-items:center;flex-wrap:wrap}.custom-time input{height:28px;border:1px solid #b8c4cc}.custom-time button{height:28px;background:#607d8b;color:#fff;border:1px solid #455a64}.chips{display:flex;flex-wrap:wrap;gap:5px}.chip{background:#e8f6ef;border:1px solid #b8dfc9;color:#1e824c;padding:3px 7px;border-radius:12px}.chip a{color:#b03a2e;margin-left:6px;text-decoration:none;font-weight:bold}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:12px;padding:0 10px 34px;grid-auto-flow:dense}.card{background:linear-gradient(180deg,#ffffff 0%,#f7fafc 100%);border:1px solid #c1ccd4;min-height:410px;position:relative;box-shadow:0 6px 18px rgba(38,56,69,.16);border-radius:7px;overflow:hidden}.card-head{height:42px;display:flex;align-items:center;justify-content:space-between;padding:0 12px;border-bottom:1px solid #dce5eb;background:linear-gradient(180deg,#fbfdff,#edf5fa)}.device-info{display:flex;align-items:center;gap:8px;padding:5px 12px;background:#f5fbfe;border-bottom:1px solid #dcebf2;color:#496676;font-size:12px}.device-info .ip-badge{display:inline-block;padding:2px 8px;border-radius:10px;background:#dff3fb;border:1px solid #a9d8e8;color:#075d7a;font-weight:800}.device-info .host-label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}body.dark .device-info,body.theme-noc .device-info{background:#0c1d27;border-bottom-color:#244454;color:#b9d7e5}body.dark .device-info .ip-badge,body.theme-noc .device-info .ip-badge{background:#123b4d;border-color:#24647d;color:#8eefff}.title{font-weight:800;color:#18384c;font-size:16px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:88%;letter-spacing:.1px}.tools button{border:0;background:transparent;color:#78909c;cursor:pointer}.card.dragging{opacity:.55;transform:scale(.985);box-shadow:0 0 0 2px rgba(52,152,219,.45),0 10px 26px rgba(52,152,219,.20);pointer-events:none}.card.drag-over{outline:2px dashed #3498db;outline-offset:-6px}.card-head{cursor:grab}.card.dragging .card-head{cursor:grabbing}.drag-ghost-placeholder{border:2px dashed #3498db;background:rgba(52,152,219,.10);border-radius:7px;min-height:260px}.card.drag-floating{position:fixed!important;z-index:99999!important;pointer-events:none!important;box-shadow:0 18px 38px rgba(0,0,0,.30)!important;opacity:.92;transform:rotate(.2deg)}.tools,.tools *{cursor:auto}.drag-hint{display:inline-flex;align-items:center;justify-content:center;font-size:14px;font-weight:900;color:#2f6078;margin-left:4px;border:1px solid #9bb8c8;background:#edf8fd;border-radius:4px;padding:2px 8px;cursor:grab;user-select:none;touch-action:none}.drag-hint:active{cursor:grabbing}.drag-placeholder{border:2px dashed #3498db;background:rgba(52,152,219,.08);border-radius:7px;min-height:180px}.card.drag-floating{position:fixed!important;z-index:9998!important;pointer-events:none!important;opacity:.88;box-shadow:0 15px 35px rgba(0,0,0,.28)!important;transform:rotate(.25deg)}.card.custom-dim{resize:both;overflow:hidden;min-width:360px;min-height:300px;max-width:100%}.resize-handle{position:absolute;right:4px;bottom:4px;width:16px;height:16px;cursor:nwse-resize;opacity:.55;background:linear-gradient(135deg,transparent 0 45%,#7f98a8 46% 55%,transparent 56%),linear-gradient(135deg,transparent 0 63%,#7f98a8 64% 72%,transparent 73%);z-index:20}.resize-handle:hover{opacity:1}.card.resizing{user-select:none;box-shadow:0 0 0 2px rgba(52,152,219,.35),0 8px 24px rgba(52,152,219,.20)}.card.custom-dim .chart{height:calc(100% - 150px);min-height:170px}.layout-tools{display:inline-flex;gap:4px;margin-left:4px}.layout-tools button{background:#eef6fb!important;color:#2c5064!important;border:1px solid #b7cad6!important}.tools{display:flex;align-items:center;gap:4px}.size-tools{display:inline-flex;align-items:center;gap:2px;margin-right:6px}.size-tools button{font-size:10px;line-height:1;border:1px solid #b7cad6;background:#f4f9fc;color:#2c5064;border-radius:3px;padding:3px 5px;min-width:22px;cursor:pointer}.size-tools button:hover{background:#dff2fb}.card.size-s{min-height:330px}.card.size-s .chart{height:185px}.card.size-m{min-height:410px}.card.size-m .chart{height:260px}.card.size-l{min-height:520px}.card.size-l .chart{height:360px}.card.size-xl{min-height:640px}.card.size-xl .chart{height:470px}.card.size-wide{grid-column:span 2}.card.size-wide .chart{height:320px}.card.size-full{grid-column:1/-1}.card.size-full .chart{height:420px}body.tv .card.size-full .chart{height:520px}body.tv .card.size-wide .chart{height:420px}.chart{height:260px;margin:4px 12px 0;display:block;width:calc(100% - 24px);background:linear-gradient(180deg,#ffffff,#f4f8fb);border-bottom:1px solid #eef2f5;border-radius:4px}.legend-table{width:calc(100% - 24px);border-collapse:collapse;margin:4px 12px 10px;table-layout:fixed;font-size:13px}.legend-table td{padding:2px 3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;border-bottom:1px solid #f0f3f5}.legend-table .name{width:54%}.num{text-align:right;font-weight:700;color:#21313b}.rxcur,.txcur{font-weight:800;font-size:13px}.rxcur{color:#008c7a}.txcur{color:#1976b9}.sw{display:inline-block;width:10px;height:4px;margin-right:5px}.rx{background:#1abc9c}.tx{background:#3498db}.disc{background:#c7b500}.err{background:#f39c12}.status{position:absolute;right:8px;bottom:6px;font-size:11px;color:#83919a}.graph-unit{display:none}.unitrx{color:#00a98f}.unittx{color:#248bd2}.chart-tooltip{display:none;position:absolute;z-index:50;pointer-events:none;background:rgba(17,34,48,.94);color:#fff;border:1px solid rgba(255,255,255,.18);border-radius:8px;padding:7px 9px;font-size:12px;box-shadow:0 6px 18px rgba(0,0,0,.28);line-height:1.45}.chart-tooltip b{color:#8ff5e4}.chart-tooltip .txv{color:#8cccff}.card.hovering .chart-tooltip{display:block}.badge{padding:2px 6px;border-radius:10px;background:#e8f6ef;color:#1e824c;font-weight:bold}.empty{padding:32px;text-align:center;background:#fff;border:1px solid #d4dce2;grid-column:1/-1}.warnmsg{color:#b36b00;font-size:11px;margin-left:8px}footer{position:fixed;bottom:0;left:0;right:0;background:#263845;color:#d9e3ea;height:24px;line-height:24px;padding:0 10px}
.exit-tv{display:none;position:fixed;right:16px;top:14px;z-index:9999;background:#e74c3c;color:#fff;border:0;border-radius:18px;padding:8px 14px;font-weight:bold;box-shadow:0 3px 12px rgba(0,0,0,.25);cursor:pointer}body.tv .exit-tv{display:block}body.theme-noc{background:#050b10;color:#d8f4ff}body.theme-noc .topbar{background:#02080d;border-bottom-color:#00e5ff}body.theme-noc .toolbar,body.theme-noc .kpi,body.theme-noc .topbox,body.theme-noc .card{background:#0b1720;color:#d8f4ff;border-color:#1a3a4d}body.theme-noc .card{background:linear-gradient(180deg,#0d1f2b,#07131a);box-shadow:0 0 18px rgba(0,229,255,.12)}body.theme-noc .card-head{background:linear-gradient(180deg,#122c3a,#0b1b25);border-bottom-color:#1a3a4d}body.theme-noc .title,body.theme-noc .num{color:#e6fbff}body.theme-noc .topbox h3{color:#8eefff}body.theme-ocean{background:#e8f6fb;color:#133242}body.theme-ocean .topbar{background:#0b5d7a;border-bottom-color:#00b8d4}body.theme-ocean .toolbar,body.theme-ocean .kpi,body.theme-ocean .topbox,body.theme-ocean .card{border-color:#a8d9e8}body.theme-ocean .card-head{background:linear-gradient(180deg,#e8fbff,#d8f2f8)}body.dark{background:#0f1b24;color:#dbe8ef}body.dark .topbar{background:#07131c;border-bottom-color:#00a98f}body.dark .toolbar,body.dark .kpi,body.dark .card{background:#142330;color:#dbe8ef;border-color:#263b4b}body.dark .card{background:linear-gradient(180deg,#182b38,#10202b);box-shadow:0 8px 22px rgba(0,0,0,.35)}body.dark .card-head{background:linear-gradient(180deg,#203746,#162936);border-bottom-color:#284252}body.dark .title,body.dark .num{color:#e8f4f8}body.dark .legend-table td{border-bottom-color:#233846}body.tv .topbar p,body.tv .toolbar,body.tv footer{display:none}body.tv .grid{grid-template-columns:repeat(auto-fill,minmax(700px,1fr));padding-top:10px}body.tv .card{min-height:440px}body.tv .chart{height:290px}.card.th-ok{border-top:5px solid #15b884}.card.th-warn{border-top:5px solid #f5b041}.card.th-crit{border-top:5px solid #e74c3c;box-shadow:0 0 0 1px rgba(231,76,60,.18),0 8px 22px rgba(231,76,60,.18)}.top-panel{margin:0 10px 10px;display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.topbox{background:#fff;border:1px solid #c9d4dc;border-radius:6px;padding:8px;box-shadow:0 2px 8px rgba(38,56,69,.08)}body.dark .topbox{background:#142330;border-color:#263b4b}.topbox h3{margin:0 0 6px;font-size:13px;color:#344d5d}body.dark .topbox h3{color:#dbe8ef}.topitem{display:flex;justify-content:space-between;gap:8px;border-bottom:1px solid #edf2f5;padding:3px 0;white-space:nowrap;overflow:hidden}.topitem span:first-child{overflow:hidden;text-overflow:ellipsis}.topitem b{font-size:12px}.p95row td{font-weight:800;color:#604080}.btn-dark{background:#34495e!important}.btn-tv{background:#8e44ad!important}.btn-export{background:#16a085!important}
@media(max-width:900px){.toolbar-row.main-search{grid-template-columns:1fr}.toolbar-row.actions{align-items:stretch}.toolbar-row.actions>*{flex:1 1 140px}.toolbar-row.profiles>*{flex:1 1 180px}.top-panel{grid-template-columns:1fr}}@media(max-width:1200px){.grid{grid-template-columns:repeat(2,minmax(320px,1fr))}.summary{grid-template-columns:repeat(3,1fr)}}@media(max-width:760px){.grid{grid-template-columns:1fr}.summary{grid-template-columns:repeat(2,1fr)}.toolbar{grid-template-columns:1fr}.topbar{align-items:flex-start;flex-direction:column}}

/* ===== Advanced GUI v34 ===== */
:root{--bg:#eef3f8;--panel:rgba(255,255,255,.88);--line:#d9e4ec;--text:#142b3b;--muted:#6c8290;--cyan:#00a7c4;--blue:#1769e0;--green:#00a878;--red:#e5484d;--amber:#ef9f27;--violet:#7c5cff;--shadow:0 12px 35px rgba(26,55,75,.11)}
html{scroll-behavior:smooth}body{background:radial-gradient(circle at 10% -10%,rgba(23,105,224,.13),transparent 28%),radial-gradient(circle at 95% 5%,rgba(0,167,196,.12),transparent 24%),var(--bg);color:var(--text);min-height:100vh}
body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.32;background-image:linear-gradient(rgba(72,112,138,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(72,112,138,.045) 1px,transparent 1px);background-size:28px 28px;z-index:-1}
.topbar{position:sticky;top:0;z-index:1000;min-height:74px;padding:12px 18px;background:linear-gradient(120deg,rgba(10,30,46,.97),rgba(13,65,86,.96) 55%,rgba(15,92,107,.95));border:0;box-shadow:0 9px 28px rgba(4,25,38,.24);backdrop-filter:blur(18px)}
.brand-wrap{display:flex;align-items:center;gap:12px}.brand-icon{width:44px;height:44px;border-radius:14px;display:grid;place-items:center;font-size:22px;color:#fff;background:linear-gradient(145deg,#16c9d8,#1769e0);box-shadow:0 0 0 4px rgba(255,255,255,.09),0 8px 22px rgba(0,199,218,.25)}
.topbar h1{font-size:21px;letter-spacing:.2px;margin:0}.topbar p{margin-top:4px;color:#bcd2df}.header-right{display:flex;align-items:center;gap:12px}.live-pill{display:inline-flex;align-items:center;gap:7px;background:rgba(15,190,135,.14);border:1px solid rgba(80,232,184,.35);color:#9bf1d2;border-radius:999px;padding:7px 11px;font-weight:800}.live-dot{width:8px;height:8px;border-radius:50%;background:#39e6ab;box-shadow:0 0 0 5px rgba(57,230,171,.12);animation:pulseLive 1.8s infinite}@keyframes pulseLive{50%{box-shadow:0 0 0 9px rgba(57,230,171,0)}}.clock{font-size:15px;padding:8px 12px;border-radius:10px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.13)}
.summary{gap:12px;padding:14px 12px}.kpi{position:relative;overflow:hidden;min-height:92px;padding:14px 16px 12px 58px;border:1px solid rgba(205,220,230,.9);border-left:0;border-radius:15px;background:linear-gradient(145deg,rgba(255,255,255,.97),rgba(246,250,253,.9));box-shadow:0 7px 24px rgba(31,62,81,.08);transition:.22s ease}.kpi:hover{transform:translateY(-3px);box-shadow:var(--shadow)}.kpi:before{position:absolute;left:14px;top:20px;width:32px;height:32px;border-radius:10px;display:grid;place-items:center;color:#fff;font-size:16px;font-weight:900;background:#647b8a;box-shadow:0 7px 15px rgba(31,62,81,.18)}.kpi:nth-child(1):before{content:"N"}.kpi:nth-child(2):before{content:"UP";font-size:10px;background:var(--green)}.kpi:nth-child(3):before{content:"DN";font-size:10px;background:var(--red)}.kpi:nth-child(4):before{content:"!";background:var(--amber)}.kpi:nth-child(5):before{content:"RX";font-size:10px;background:var(--blue)}.kpi:nth-child(6):before{content:"TX";font-size:10px;background:var(--violet)}.kpi:after{content:"";position:absolute;width:90px;height:90px;right:-35px;top:-40px;border-radius:50%;background:currentColor;opacity:.055}.kpi b{font-size:27px;line-height:1.1;color:#17384d}.kpi span{display:block;margin-top:5px;color:var(--muted);font-weight:700;text-transform:uppercase;font-size:10px;letter-spacing:.75px}
.toolbar{margin:0 12px 14px;padding:13px;border-radius:17px;border:1px solid rgba(201,218,229,.95);background:var(--panel);box-shadow:var(--shadow);backdrop-filter:blur(16px);gap:10px}.toolbar-row{gap:9px}.toolbar-row.main-search{grid-template-columns:minmax(220px,300px) 1fr 145px}.toolbar input,.toolbar select,.toolbar button{height:40px;border-radius:10px;border:1px solid #cbdbe5;transition:.18s ease}.toolbar input,.toolbar select{background:rgba(250,253,255,.96);color:#17384d;box-shadow:inset 0 1px 2px rgba(20,50,68,.04)}.toolbar input:focus,.toolbar select:focus{outline:0;border-color:#3a9bdc;box-shadow:0 0 0 4px rgba(58,155,220,.13)}.toolbar button{border:0;background:linear-gradient(135deg,#087dac,#086998);box-shadow:0 5px 12px rgba(8,105,152,.18);transform:translateY(0)}.toolbar button:hover{filter:none;transform:translateY(-2px);box-shadow:0 8px 16px rgba(8,105,152,.24)}.toolbar button:active{transform:translateY(0)}.toolbar-row.profiles{background:linear-gradient(120deg,rgba(234,247,253,.9),rgba(242,248,255,.9));border:1px solid #c8e1ee;border-radius:12px;padding:9px}
.range{display:flex;align-items:center;flex-wrap:wrap;gap:5px}.range:before{content:"TIME RANGE";font-size:10px;font-weight:900;letter-spacing:.8px;color:#718894;margin-right:4px}.range button{height:31px;margin:0;border-radius:8px;background:#edf4f8;color:#35566a;box-shadow:none}.range button.active{background:linear-gradient(135deg,#1769e0,#00a7c4);border:0;box-shadow:0 6px 14px rgba(23,105,224,.23)}.custom-time{padding:7px 9px;background:#f5f9fc;border:1px solid #dae6ed;border-radius:10px}.chips{max-height:88px;overflow:auto;padding:3px}.chip{padding:5px 9px;border-radius:9px;background:linear-gradient(135deg,#e7f8f2,#edf9ff);border:1px solid #bfe4d7;color:#147052;box-shadow:0 2px 7px rgba(25,105,81,.06)}
.top-panel{gap:12px;margin:0 12px 14px}.topbox{padding:12px;border-radius:15px;border:1px solid #d3e1e9;background:rgba(255,255,255,.9);box-shadow:0 8px 24px rgba(31,62,81,.08)}.topbox h3{font-size:12px;text-transform:uppercase;letter-spacing:.7px;padding-bottom:8px;border-bottom:1px solid #e4edf2;color:#2c5267}.topitem{padding:6px 3px;border-bottom:1px dashed #e2ebf0}.topitem b{padding:3px 7px;border-radius:7px;background:#eef6fb;color:#17658a}
.grid{gap:16px;padding:0 12px 48px}.card{border-radius:17px;border:1px solid rgba(198,215,226,.95);background:linear-gradient(155deg,rgba(255,255,255,.98),rgba(244,249,252,.95));box-shadow:0 10px 30px rgba(24,55,75,.11);transition:transform .22s ease,box-shadow .22s ease}.card:hover{transform:translateY(-2px);box-shadow:0 16px 38px rgba(24,55,75,.16)}.card-head{height:51px;padding:0 14px;background:linear-gradient(120deg,#f9fcfe,#eaf4f9);border-bottom:1px solid #dce8ef}.title{font-size:15px;color:#173e55}.device-info{padding:7px 14px;background:rgba(239,248,252,.86)}.device-info .ip-badge{background:linear-gradient(135deg,#dff5fb,#e8f2ff);border-color:#b6dce9;color:#086887}.tools{gap:5px}.size-tools button,.layout-tools button,.tools>button{border:1px solid #c8dbe6!important;background:#f7fbfd!important;color:#315d73!important;border-radius:7px!important;box-shadow:none!important}.drag-hint{border-radius:8px;background:#e6f5fb;border-color:#b5d8e6}.chart{border-radius:11px;background:linear-gradient(180deg,#fff,#f5fafc);box-shadow:inset 0 0 0 1px #e4edf2}.legend-table{background:rgba(255,255,255,.72);border-radius:10px;overflow:hidden}.legend-table td{padding:5px 4px}.status{right:12px;bottom:9px;padding:4px 8px;border-radius:8px;background:rgba(245,249,252,.94);border:1px solid #dbe7ed}.badge{box-shadow:inset 0 0 0 1px rgba(20,130,83,.15)}.card.th-ok{border-top:4px solid var(--green)}.card.th-warn{border-top:4px solid var(--amber)}.card.th-crit{border-top:4px solid var(--red)}
footer{height:30px;line-height:30px;background:rgba(8,31,46,.94);backdrop-filter:blur(12px);border-top:1px solid rgba(255,255,255,.08)}
body.dark,body.theme-noc{--panel:rgba(15,33,45,.91);--text:#dcecf4;--muted:#9bb2bf;background:radial-gradient(circle at 15% 0,rgba(0,196,220,.12),transparent 30%),#07131b}body.dark .kpi,body.theme-noc .kpi,body.dark .topbox,body.theme-noc .topbox{background:linear-gradient(145deg,#152936,#0e202b);border-color:#274454}body.dark .kpi b,body.theme-noc .kpi b{color:#e7f8ff}body.dark .toolbar input,body.dark .toolbar select,body.theme-noc .toolbar input,body.theme-noc .toolbar select{background:#102633;color:#dcecf4;border-color:#315163}body.dark .topitem b,body.theme-noc .topitem b{background:#183747;color:#96e9fa}
@media(max-width:900px){.topbar{position:relative}.header-right{width:100%;justify-content:space-between}.summary{grid-template-columns:repeat(2,1fr)}.toolbar-row.main-search{grid-template-columns:1fr}.card:hover{transform:none}}@media(max-width:520px){.summary{grid-template-columns:1fr 1fr;padding:8px}.kpi{padding-left:48px;min-height:82px}.kpi:before{left:10px}.kpi b{font-size:22px}.toolbar{margin:0 8px 10px}.top-panel{margin-left:8px;margin-right:8px}.grid{padding-left:8px;padding-right:8px}.brand-icon{display:none}.live-pill{display:none}}

/* ===== Network icon + premium bandwidth palette v35 ===== */
:root{--rx:#00d6a3;--rx-dark:#00a982;--rx-soft:rgba(0,214,163,.14);--tx:#6c63ff;--tx-dark:#5147e8;--tx-soft:rgba(108,99,255,.14)}
.brand-icon{overflow:visible;background:linear-gradient(145deg,#0b2032,#123f5a);border:1px solid rgba(93,228,255,.42);box-shadow:0 0 0 4px rgba(44,204,231,.08),0 9px 25px rgba(0,183,223,.24)}.brand-icon svg{width:34px;height:34px;overflow:visible}.net-link{fill:none;stroke:#8eefff;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round;filter:drop-shadow(0 0 3px rgba(80,226,255,.75))}.net-node{stroke:#eaffff;stroke-width:1.2}.node-a,.node-e{fill:#00d6a3}.node-b,.node-g{fill:#19bde8}.node-c,.node-f{fill:#8b7cff}.node-d{fill:#fff;filter:drop-shadow(0 0 5px #51e7ff);transform-origin:24px 24px;animation:netPulse 1.8s ease-in-out infinite}@keyframes netPulse{50%{transform:scale(1.28);fill:#bafff0}}
.kpi:nth-child(5):before{background:linear-gradient(145deg,var(--rx),var(--rx-dark));box-shadow:0 7px 18px rgba(0,214,163,.3)}.kpi:nth-child(6):before{background:linear-gradient(145deg,#8b7cff,var(--tx-dark));box-shadow:0 7px 18px rgba(108,99,255,.3)}.kpi:nth-child(5){border-color:rgba(0,214,163,.25)}.kpi:nth-child(6){border-color:rgba(108,99,255,.25)}.kpi:nth-child(5) b{color:#008e6d}.kpi:nth-child(6) b{color:#5147e8}
.rxcur,.unitrx{color:var(--rx-dark)!important}.txcur,.unittx{color:var(--tx-dark)!important}.sw.rx{height:6px;border-radius:6px;background:linear-gradient(90deg,#00b98d,var(--rx));box-shadow:0 0 8px rgba(0,214,163,.35)}.sw.tx{height:6px;border-radius:6px;background:linear-gradient(90deg,#5147e8,#8b7cff);box-shadow:0 0 8px rgba(108,99,255,.35)}
.chart-tooltip b{color:#68f5d3}.chart-tooltip .txv{color:#b9b5ff}.p95rx{color:#008e6d!important}.p95tx{color:#5b52ef!important}
body.dark .kpi:nth-child(5) b,body.theme-noc .kpi:nth-child(5) b{color:#4bf0c8}body.dark .kpi:nth-child(6) b,body.theme-noc .kpi:nth-child(6) b{color:#aaa4ff}body.dark .rxcur,body.theme-noc .rxcur{color:#4bf0c8!important}body.dark .txcur,body.theme-noc .txcur{color:#aaa4ff!important}

/* ===== v36 Advanced Device Identity + Telemetry HUD ===== */
.device-info{display:flex;align-items:center;gap:7px;min-height:43px;padding:7px 13px;background:linear-gradient(90deg,rgba(239,249,252,.96),rgba(245,246,255,.92));overflow:hidden}.device-name-badge,.iface-badge,.alias-badge{display:inline-flex;align-items:center;height:26px;padding:0 9px;border-radius:8px;border:1px solid #c9dde8;background:rgba(255,255,255,.82);color:#36596d;font-weight:750;white-space:nowrap}.device-name-badge{min-width:0;max-width:45%;color:#16465d}.device-name-badge i{width:8px;height:8px;flex:0 0 auto;margin-right:7px;border-radius:50%;background:#00c892;box-shadow:0 0 0 4px rgba(0,200,146,.12)}.host-label{overflow:hidden;text-overflow:ellipsis}.ip-badge{height:26px!important;display:inline-flex!important;align-items:center;padding:0 9px!important;border-radius:8px!important;background:linear-gradient(135deg,#dcf7ff,#e7efff)!important;color:#086786!important}.iface-badge{color:#584bd1;border-color:#d2cdf7;background:#f2f0ff}.alias-badge{min-width:0;overflow:hidden;text-overflow:ellipsis;color:#8a5a08;border-color:#f0ddba;background:#fff8e9}
.metric-strip{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px;padding:8px 12px 3px}.mini-metric{position:relative;overflow:hidden;padding:7px 9px;border:1px solid #dbe7ed;border-radius:10px;background:linear-gradient(145deg,#fff,#f5f9fb)}.mini-metric:after{content:"";position:absolute;width:40px;height:40px;right:-14px;top:-18px;border-radius:50%;background:currentColor;opacity:.08}.mini-metric span{display:block;font-size:8px;letter-spacing:.75px;color:#78909d;font-weight:900}.mini-metric b{display:block;margin-top:3px;font-size:12px;color:#28495b;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.rx-metric{border-left:3px solid var(--rx)}.rx-metric b{color:#008e6d}.tx-metric{border-left:3px solid var(--tx)}.tx-metric b{color:#5147e8}.util-metric{border-left:3px solid #ff9f43}.speed-metric{border-left:3px solid #18a0c9}
.card{isolation:isolate}.card:before{content:"";position:absolute;left:0;right:0;top:0;height:3px;z-index:5;background:linear-gradient(90deg,var(--rx),#16bde0 48%,var(--tx));opacity:.9}.card-head{background:linear-gradient(100deg,rgba(249,253,255,.98),rgba(238,246,252,.98) 54%,rgba(245,242,255,.98))}.title:before{content:"";display:inline-block;width:5px;height:16px;margin-right:8px;vertical-align:-3px;border-radius:5px;background:linear-gradient(180deg,var(--rx),var(--tx))}.chart{margin-top:7px}.legend-table{border:1px solid #e0eaf0}.legend-table tr:hover td{background:rgba(235,247,252,.7)}.legend-table td:nth-child(n+2){font-variant-numeric:tabular-nums}.status{display:flex;align-items:center;gap:5px;box-shadow:0 4px 13px rgba(25,55,75,.08)}
body.dark .device-info,body.theme-noc .device-info{background:linear-gradient(90deg,#102b37,#171f3b)}body.dark .device-name-badge,body.dark .iface-badge,body.dark .alias-badge,body.theme-noc .device-name-badge,body.theme-noc .iface-badge,body.theme-noc .alias-badge{background:#142e3b;border-color:#315466;color:#d8edf6}body.dark .mini-metric,body.theme-noc .mini-metric{background:linear-gradient(145deg,#142c39,#0e202b);border-color:#2b4858}body.dark .mini-metric b,body.theme-noc .mini-metric b{color:#e1f3fa}body.dark .rx-metric b,body.theme-noc .rx-metric b{color:#4bf0c8}body.dark .tx-metric b,body.theme-noc .tx-metric b{color:#aaa4ff}
@media(max-width:700px){.metric-strip{grid-template-columns:repeat(2,1fr)}.device-name-badge{max-width:100%;flex:1}.alias-badge{display:none}}@media(max-width:460px){.iface-badge{display:none}.device-info{flex-wrap:wrap}.metric-strip{gap:5px;padding-left:8px;padding-right:8px}}

/* ===== v37 Server Rack Brand Icon ===== */
.brand-icon.server-rack-icon{background:linear-gradient(145deg,#081b2b,#103d58);border:1px solid rgba(94,230,255,.48);box-shadow:0 0 0 4px rgba(44,204,231,.08),0 10px 26px rgba(0,183,223,.24)}
.server-rack-icon svg{width:36px;height:36px;overflow:visible}.rack-frame{fill:rgba(7,24,36,.68);stroke:#92efff;stroke-width:1.6}.rack-unit{stroke-width:1}.rack-unit-1{fill:#153b4c;stroke:#27dbb0}.rack-unit-2{fill:#1d3454;stroke:#7d75ff}.rack-unit-3{fill:#153b4c;stroke:#28bce8}.rack-led{stroke:#eaffff;stroke-width:.7}.led-1{fill:#00e5ad;filter:drop-shadow(0 0 3px #00e5ad)}.led-2{fill:#8f86ff;filter:drop-shadow(0 0 3px #8f86ff)}.led-3{fill:#32c7eb;filter:drop-shadow(0 0 3px #32c7eb)}.rack-slot{fill:none;stroke:#a9cdda;stroke-width:1.5;stroke-linecap:round}.activity-wave{fill:none;stroke:#ffffff;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;filter:drop-shadow(0 0 4px #40e8ff);stroke-dasharray:52;animation:rackActivity 2.1s linear infinite}@keyframes rackActivity{0%{stroke-dashoffset:52;opacity:.35}35%,75%{opacity:1}100%{stroke-dashoffset:0;opacity:.35}}

/* ===== v38 Operations Command Deck ===== */
.command-deck{position:relative;z-index:20;display:grid;grid-template-columns:1.35fr repeat(4,minmax(105px,.75fr)) auto;align-items:stretch;gap:8px;margin:12px 12px 0;padding:9px;border:1px solid rgba(193,215,227,.92);border-radius:15px;background:linear-gradient(135deg,rgba(255,255,255,.94),rgba(238,247,252,.9));box-shadow:0 9px 28px rgba(21,52,71,.09);backdrop-filter:blur(14px)}.command-health,.command-stat{display:flex;align-items:center;gap:10px;min-width:0;padding:7px 10px;border-right:1px solid #dce8ee}.command-health small,.command-stat small{display:block;color:#7b919d;font-size:8px;font-weight:900;letter-spacing:.8px}.command-health b,.command-stat b{display:block;margin-top:3px;overflow:hidden;color:#24475a;font-size:11px;white-space:nowrap;text-overflow:ellipsis}.health-ring{position:relative;width:28px;height:28px;flex:0 0 28px;border:2px solid rgba(0,200,146,.25);border-radius:50%;display:grid;place-items:center}.health-ring:before{content:"";position:absolute;inset:-2px;border:2px solid transparent;border-top-color:#00d6a3;border-right-color:#00d6a3;border-radius:50%;animation:healthSpin 2.4s linear infinite}.health-ring i{width:8px;height:8px;border-radius:50%;background:#00d6a3;box-shadow:0 0 0 5px rgba(0,214,163,.12),0 0 12px rgba(0,214,163,.7)}@keyframes healthSpin{to{transform:rotate(360deg)}}.command-actions{display:flex;align-items:center;gap:6px}.command-actions button{height:32px;padding:0 10px;border:1px solid #c6dbe6;border-radius:8px;background:#f7fbfd;color:#315d73;font-size:10px;font-weight:800;cursor:pointer;transition:.18s}.command-actions button:hover{transform:translateY(-1px);border-color:#75bfd7;background:#eaf7fb}.command-actions button.active{border-color:#f0b55c;background:#fff4df;color:#995f00}.command-actions #manualRefreshBtn{border:0;color:#fff;background:linear-gradient(135deg,#087da9,#6559ed);box-shadow:0 5px 13px rgba(56,92,185,.2)}
body.compact-dashboard .card{min-height:340px}body.compact-dashboard .device-info{min-height:36px;padding-top:5px;padding-bottom:5px}body.compact-dashboard .metric-strip{display:none}body.compact-dashboard .chart{height:205px}body.compact-dashboard .legend-table tr:nth-child(n+4){display:none}body.compact-dashboard .grid{grid-template-columns:repeat(auto-fill,minmax(340px,1fr))}
body.dark .command-deck,body.theme-noc .command-deck{background:linear-gradient(135deg,rgba(12,31,42,.96),rgba(15,39,54,.92));border-color:#294958}body.dark .command-health,body.dark .command-stat,body.theme-noc .command-health,body.theme-noc .command-stat{border-color:#294958}body.dark .command-health b,body.dark .command-stat b,body.theme-noc .command-health b,body.theme-noc .command-stat b{color:#dff4fb}body.dark .command-actions button,body.theme-noc .command-actions button{background:#15313f;border-color:#315467;color:#d3e9f2}
@media(max-width:1150px){.command-deck{grid-template-columns:repeat(3,1fr)}.command-stat{border-right:0}.command-actions{grid-column:span 2;justify-content:flex-end}}@media(max-width:700px){.command-deck{grid-template-columns:1fr 1fr}.command-health{grid-column:1/-1}.command-actions{grid-column:1/-1;justify-content:stretch}.command-actions button{flex:1}.command-stat:nth-of-type(4),.command-stat:nth-of-type(5){display:none}}

/* ===== v39 Ultra Compact Desktop + Auto Fit ===== */
:root{--desktop-card-min:318px;--desktop-gap:10px}
.grid{grid-template-columns:repeat(auto-fit,minmax(var(--desktop-card-min),1fr));gap:var(--desktop-gap)}
.card{min-width:0}.card.size-m{min-height:374px}.card.size-m .chart{height:220px}.card-head{height:45px}.title{font-size:13px}.tools{gap:3px}.size-tools{margin-right:2px}.size-tools button{padding:2px 4px;min-width:20px}.layout-tools button{font-size:9px;padding-left:6px!important;padding-right:6px!important}.drag-hint{font-size:11px;padding:2px 6px;margin-left:1px}.device-info{min-height:38px;padding:5px 10px}.metric-strip{gap:5px;padding:6px 9px 2px}.mini-metric{padding:5px 7px}.mini-metric span{font-size:7px}.mini-metric b{font-size:11px}.chart{margin-left:8px;margin-right:8px;width:calc(100% - 16px)}.legend-table{width:calc(100% - 16px);margin-left:8px;margin-right:8px;font-size:11px}.legend-table td{padding:3px}.command-deck{margin-top:8px}.summary{padding-top:9px;padding-bottom:9px}.kpi{min-height:79px;padding-top:11px;padding-bottom:9px}.kpi b{font-size:23px}.top-panel{margin-bottom:10px}.topbox{padding:9px}.toolbar{padding:9px;margin-bottom:10px}.toolbar input,.toolbar select,.toolbar button{height:36px}.toolbar-row.profiles{padding:6px}
/* Auto Fit is enabled by default for normal 100% desktop usage. */
body.auto-fit .grid{grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:9px}body.auto-fit .card.size-wide{grid-column:span 2}body.auto-fit .card.size-full{grid-column:1/-1}body.auto-fit .metric-strip{grid-template-columns:repeat(4,minmax(0,1fr))}
/* Large desktop: show more cards at browser 100% without shrinking text excessively. */
@media(min-width:1360px){body.auto-fit{--desktop-card-min:300px}.summary{grid-template-columns:repeat(6,1fr)}.top-panel{grid-template-columns:repeat(3,1fr)}}
@media(min-width:1600px){body.auto-fit{--desktop-card-min:340px;--desktop-gap:11px}body.auto-fit .card.size-m .chart{height:235px}}
@media(min-width:1900px){body.auto-fit{--desktop-card-min:360px}.command-deck{grid-template-columns:1.3fr repeat(4,.72fr) auto}}
/* Focus mode: keep operations bar visible, hide controls and overview panels. */
body.focus-dashboard .toolbar,body.focus-dashboard .summary,body.focus-dashboard .top-panel{display:none}body.focus-dashboard .command-deck{position:sticky;top:78px;z-index:990;margin-bottom:10px}body.focus-dashboard .grid{padding-top:0}body.focus-dashboard footer{opacity:.72}
/* Cleaner card tool buttons until hover. */
.card .tools{opacity:.62;transition:opacity .18s}.card:hover .tools,.card:focus-within .tools{opacity:1}.card:hover .device-info{background:linear-gradient(90deg,rgba(232,249,247,.96),rgba(241,240,255,.95))}
/* Smart activity rail on the left of every widget. */
.card:after{content:"";position:absolute;left:0;top:52px;bottom:12px;width:2px;border-radius:0 3px 3px 0;background:linear-gradient(180deg,var(--rx),transparent 48%,var(--tx));opacity:.42}.card.th-warn:after{background:linear-gradient(180deg,#ffb347,#ff8c42)}.card.th-crit:after{background:linear-gradient(180deg,#ff5c6c,#d92f45);opacity:.9}
body.dark .card:hover .device-info,body.theme-noc .card:hover .device-info{background:linear-gradient(90deg,#103339,#201f45)}
@media(max-width:1359px){body.auto-fit .grid{grid-template-columns:repeat(auto-fit,minmax(300px,1fr))}.command-health,.command-stat{padding-left:7px;padding-right:7px}.command-actions button{padding-left:7px;padding-right:7px}}
@media(max-width:1050px){body.auto-fit .grid{grid-template-columns:repeat(2,minmax(280px,1fr))}.command-deck{grid-template-columns:repeat(3,1fr)}}
@media(max-width:680px){body.auto-fit .grid{grid-template-columns:1fr}.metric-strip{grid-template-columns:repeat(2,1fr)!important}.command-actions{overflow-x:auto}.command-actions button{min-width:78px}.card .tools{opacity:1}}

/* ===== v40 NOC Intelligence Suite ===== */
.alert-overlay{position:fixed;right:18px;top:84px;z-index:12000;display:flex;flex-direction:column;gap:8px;width:min(390px,calc(100vw - 30px));pointer-events:none}.noc-alert{pointer-events:auto;display:grid;grid-template-columns:34px 1fr auto;align-items:center;gap:10px;padding:10px 11px;border:1px solid rgba(255,255,255,.18);border-radius:12px;color:#fff;background:linear-gradient(135deg,rgba(144,30,42,.97),rgba(79,19,31,.97));box-shadow:0 14px 35px rgba(40,10,15,.32);animation:alertIn .3s ease}.noc-alert.warn{background:linear-gradient(135deg,rgba(177,103,14,.97),rgba(99,53,6,.97))}.noc-alert .alert-icon{width:32px;height:32px;display:grid;place-items:center;border-radius:9px;background:rgba(255,255,255,.13);font-weight:900}.noc-alert b{display:block;font-size:11px}.noc-alert small{display:block;margin-top:3px;color:rgba(255,255,255,.78)}.noc-alert button{border:0;background:transparent;color:#fff;font-size:17px;cursor:pointer}@keyframes alertIn{from{opacity:0;transform:translateX(25px)}}
.intel-strip{display:grid;grid-template-columns:repeat(3,1fr);gap:5px;padding:4px 9px 0}.intel{display:flex;justify-content:space-between;gap:5px;padding:4px 7px;border:1px solid #dce8ee;border-radius:7px;background:rgba(255,255,255,.76);color:#718894;font-size:8px;font-weight:900;letter-spacing:.4px}.intel b{color:#274b5e;font-size:9px;letter-spacing:0}.sla-intel{border-left:3px solid #00c892}.anomaly-intel.warning{border-left:3px solid #ff9f43;background:#fff6e7}.anomaly-intel.critical{border-left:3px solid #ef4858;background:#fff0f2}.forecast-intel{border-left:3px solid #6c63ff}
.card.pinned-critical{order:-1000;box-shadow:0 0 0 2px rgba(239,72,88,.3),0 15px 36px rgba(150,30,45,.2)}.card.pinned-critical .title:after{content:" PINNED";margin-left:7px;padding:2px 5px;border-radius:5px;color:#fff;background:#e54858;font-size:7px;vertical-align:2px}.card.anomaly-flash{animation:anomalyPulse 1.6s ease-in-out 2}@keyframes anomalyPulse{50%{box-shadow:0 0 0 3px rgba(255,159,67,.35),0 16px 38px rgba(255,130,30,.2)}}
body.widget-fullscreen{overflow:hidden}body.widget-fullscreen .card:not(.widget-expanded){display:none}body.widget-fullscreen .grid{position:fixed;inset:0;z-index:15000;padding:14px;background:#edf4f8;display:block}body.widget-fullscreen .card.widget-expanded{width:100%!important;height:calc(100vh - 28px)!important;max-width:none;display:block;transform:none}body.widget-fullscreen .card.widget-expanded .chart{height:calc(100vh - 330px)!important;min-height:300px}.exit-widget-fullscreen{display:none;position:fixed;right:25px;top:22px;z-index:16000;border:0;border-radius:9px;padding:8px 12px;color:#fff;background:#e54858;font-weight:800;cursor:pointer}body.widget-fullscreen .exit-widget-fullscreen{display:block}
body.dark .intel,body.theme-noc .intel{background:#102835;border-color:#294958;color:#91adba}body.dark .intel b,body.theme-noc .intel b{color:#e0f5fc}body.dark.widget-fullscreen .grid,body.theme-noc.widget-fullscreen .grid{background:#07131b}
@media(max-width:680px){.intel-strip{grid-template-columns:1fr}.forecast-intel{display:none}.alert-overlay{right:8px;top:70px}}

/* ===== v41 Incident Timeline + Port Health Score ===== */
.intel-strip{grid-template-columns:repeat(5,minmax(0,1fr))}.health-score,.timeline-open{display:grid;grid-template-columns:1fr auto;grid-template-rows:auto auto;align-items:center;gap:1px 5px;min-width:0;padding:4px 7px;border:1px solid #cfe3dc;border-left:3px solid #00c892;border-radius:7px;background:linear-gradient(145deg,#f3fff9,#fff);color:#67857a;cursor:pointer;text-align:left}.health-score span,.timeline-open span{font-size:8px;font-weight:900;letter-spacing:.5px}.health-score b,.timeline-open b{grid-row:1/3;grid-column:2;font-size:18px;line-height:1;color:#008d69;font-variant-numeric:tabular-nums}.health-score i,.timeline-open i{font-size:8px;font-style:normal;color:#799087}.health-score.degraded{border-color:#f3d8aa;border-left-color:#ff9f43;background:#fff8ed}.health-score.degraded b{color:#c77314}.health-score.critical{border-color:#efb8c0;border-left-color:#e54858;background:#fff1f3}.health-score.critical b{color:#d52e41}.timeline-open{border-color:#d6d2f5;border-left-color:#6c63ff;background:linear-gradient(145deg,#f5f3ff,#fff);color:#655ca6}.timeline-open b{color:#5449df}.timeline-open:hover,.health-score:hover{transform:translateY(-1px);box-shadow:0 5px 13px rgba(34,68,88,.12)}
.incident-modal{display:none;position:fixed;inset:0;z-index:20000;padding:28px;background:rgba(5,18,28,.72);backdrop-filter:blur(9px)}.incident-modal.open{display:grid;place-items:center}.incident-dialog{width:min(760px,96vw);max-height:90vh;display:flex;flex-direction:column;overflow:hidden;border:1px solid rgba(188,218,231,.7);border-radius:18px;background:#f8fbfd;box-shadow:0 30px 80px rgba(0,0,0,.42)}.incident-head{display:flex;align-items:center;justify-content:space-between;padding:15px 18px;color:#fff;background:linear-gradient(120deg,#09283b,#0b6579 58%,#5549d9)}.incident-head small{font-size:8px;letter-spacing:1px;color:#9fdae7}.incident-head h3{margin:3px 0 0;font-size:16px}.incident-head button{width:32px;height:32px;border:1px solid rgba(255,255,255,.25);border-radius:9px;background:rgba(255,255,255,.1);color:#fff;font-size:20px;cursor:pointer}.incident-summary{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;padding:10px 14px;border-bottom:1px solid #dce7ed}.incident-summary span{padding:8px 10px;border:1px solid #dae6ec;border-radius:9px;background:#fff;color:#718794;font-size:9px;font-weight:800}.incident-summary b{float:right;color:#25495c;font-size:12px}.incident-timeline-body{min-height:190px;overflow:auto;padding:12px 18px 16px}.timeline-empty{padding:50px 10px;text-align:center;color:#82949e}.timeline-event{position:relative;margin-left:11px;padding:0 0 15px 23px;border-left:2px solid #dce7ed}.timeline-event:last-child{padding-bottom:0}.timeline-event:before{content:"";position:absolute;left:-6px;top:3px;width:10px;height:10px;border:2px solid #fff;border-radius:50%;background:#00c892;box-shadow:0 0 0 2px #bdeada}.timeline-event.warning:before{background:#ff9f43;box-shadow:0 0 0 2px #ffe0b8}.timeline-event.critical:before{background:#e54858;box-shadow:0 0 0 2px #f7c5cb}.timeline-event.recovery:before{background:#28a9d1;box-shadow:0 0 0 2px #c3eaf5}.timeline-event-head{display:flex;justify-content:space-between;gap:10px}.timeline-event-head b{font-size:11px;color:#294b5d}.timeline-event-head time{font-size:9px;color:#879aa5}.timeline-event p{margin:3px 0;color:#607a89;font-size:10px}.timeline-event small{color:#91a1aa}.incident-foot{display:flex;justify-content:flex-end;gap:7px;padding:10px 14px;border-top:1px solid #dce7ed;background:#f1f7fa}.incident-foot button{height:32px;padding:0 11px;border:1px solid #c8dce6;border-radius:8px;background:#fff;color:#315d73;font-size:10px;font-weight:800;cursor:pointer}.incident-foot button:last-child{border:0;color:#fff;background:linear-gradient(135deg,#087da9,#6559ed)}
.card.health-degraded{box-shadow:0 0 0 1px rgba(255,159,67,.25),0 12px 32px rgba(171,92,12,.12)}.card.health-critical{box-shadow:0 0 0 2px rgba(229,72,88,.23),0 14px 36px rgba(145,31,45,.16)}
body.dark .health-score,body.theme-noc .health-score,body.dark .timeline-open,body.theme-noc .timeline-open{background:#102835;border-color:#315262;color:#b8d1dc}body.dark .incident-dialog,body.theme-noc .incident-dialog{background:#0d202b;border-color:#31505f}body.dark .incident-summary,body.theme-noc .incident-summary{border-color:#294653}body.dark .incident-summary span,body.theme-noc .incident-summary span{background:#132b37;border-color:#294653;color:#a7bec9}body.dark .incident-summary b,body.theme-noc .incident-summary b,body.dark .timeline-event-head b,body.theme-noc .timeline-event-head b{color:#e2f5fc}body.dark .timeline-event,body.theme-noc .timeline-event{border-color:#294653}body.dark .timeline-event p,body.theme-noc .timeline-event p{color:#9bb4c0}body.dark .incident-foot,body.theme-noc .incident-foot{background:#0a1b24;border-color:#294653}
@media(max-width:900px){.intel-strip{grid-template-columns:repeat(3,1fr)}.health-score,.timeline-open{display:grid!important}}@media(max-width:580px){.intel-strip{grid-template-columns:repeat(2,1fr)!important}.incident-modal{padding:8px}.incident-summary{grid-template-columns:1fr}.forecast-intel{display:none}.health-score b,.timeline-open b{font-size:15px}}

/* ===== v42 Interface Drawer + Health Breakdown + Performance Monitor ===== */
.intel-strip{grid-template-columns:repeat(6,minmax(0,1fr))}.details-open{display:grid;grid-template-columns:1fr auto;grid-template-rows:auto auto;align-items:center;gap:1px 5px;min-width:0;padding:4px 7px;border:1px solid #bcdde8;border-left:3px solid #18a0c9;border-radius:7px;background:linear-gradient(145deg,#eefaff,#fff);color:#377088;cursor:pointer;text-align:left}.details-open span{font-size:8px;font-weight:900;letter-spacing:.5px}.details-open b{grid-row:1/3;grid-column:2;font-size:20px;color:#1085aa}.details-open i{font-size:8px;font-style:normal}.details-open:hover{transform:translateY(-1px);box-shadow:0 5px 13px rgba(34,68,88,.12)}
.drawer-backdrop{position:fixed;inset:0;z-index:17500;background:rgba(4,17,26,.48);backdrop-filter:blur(3px);opacity:0;pointer-events:none;transition:.24s}.drawer-backdrop.open{opacity:1;pointer-events:auto}.detail-drawer{position:fixed;right:0;top:0;bottom:0;z-index:18000;width:min(520px,96vw);display:flex;flex-direction:column;background:#f6fafc;border-left:1px solid #bdd7e3;box-shadow:-22px 0 60px rgba(3,22,34,.28);transform:translateX(105%);transition:transform .28s ease}.detail-drawer.open{transform:translateX(0)}.drawer-head{display:flex;align-items:center;justify-content:space-between;padding:17px 18px;color:#fff;background:linear-gradient(125deg,#08293c,#0a687c 55%,#5a4cdf)}.drawer-head small,.performance-head small{font-size:8px;letter-spacing:1px;color:#a7e2ed}.drawer-head h3,.performance-head h3{margin:4px 0 0;font-size:17px}.drawer-head button,.performance-head button{width:33px;height:33px;border:1px solid rgba(255,255,255,.25);border-radius:9px;background:rgba(255,255,255,.1);color:#fff;font-size:20px;cursor:pointer}.drawer-body{overflow:auto;padding:13px}.drawer-section{margin-bottom:11px;padding:12px;border:1px solid #d8e5eb;border-radius:12px;background:#fff;box-shadow:0 5px 15px rgba(31,62,81,.05)}.drawer-section h4{margin:0 0 10px;color:#294d60;font-size:10px;letter-spacing:.7px}.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:7px}.detail-cell{padding:8px;border-radius:8px;background:#f3f8fa}.detail-cell span{display:block;color:#7c929e;font-size:8px;font-weight:900;letter-spacing:.4px}.detail-cell b{display:block;margin-top:4px;color:#244759;font-size:11px;overflow:hidden;text-overflow:ellipsis}.health-ring-large{--score:100;position:relative;width:116px;height:116px;margin:4px auto 14px;display:grid;place-items:center;border-radius:50%;background:conic-gradient(#00c892 calc(var(--score)*1%),#e3ecef 0)}.health-ring-large:before{content:"";position:absolute;inset:10px;border-radius:50%;background:#fff}.health-ring-large strong{position:relative;font-size:28px;color:#244759}.health-ring-large small{position:absolute;top:67px;color:#7f949f}.breakdown-row{display:grid;grid-template-columns:1fr auto;gap:8px;padding:7px 2px;border-bottom:1px dashed #e0eaef}.breakdown-row:last-child{border-bottom:0}.breakdown-row span{color:#526f7f;font-size:10px}.breakdown-row b{font-size:10px}.breakdown-row .penalty{color:#d83a4d}.breakdown-row .good-points{color:#008d69}.drawer-incidents{display:flex;flex-direction:column;gap:6px}.drawer-incident{padding:8px;border-left:3px solid #ff9f43;border-radius:7px;background:#fff7e9;color:#72511d;font-size:9px}.drawer-incident.critical{border-left-color:#e54858;background:#fff0f2;color:#8f2e3a}
.performance-panel{position:fixed;right:16px;top:78px;z-index:17000;width:min(520px,calc(100vw - 32px));display:none;overflow:hidden;border:1px solid #bcd6e2;border-radius:16px;background:#f5fafc;box-shadow:0 22px 60px rgba(4,23,35,.3)}.performance-panel.open{display:block}.performance-head{display:flex;align-items:center;justify-content:space-between;padding:13px 15px;color:#fff;background:linear-gradient(125deg,#08293c,#0a687c 55%,#5a4cdf)}.performance-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:7px;padding:11px}.performance-grid div{padding:9px;border:1px solid #d8e5eb;border-radius:9px;background:#fff}.performance-grid span{display:block;color:#7a909c;font-size:7px;font-weight:900;letter-spacing:.5px}.performance-grid b{display:block;margin-top:4px;color:#25495b;font-size:12px}.performance-foot{display:flex;align-items:center;justify-content:space-between;padding:9px 12px;border-top:1px solid #d8e5eb}.perf-status{padding:5px 8px;border-radius:8px;background:#e7f8f2;color:#087454;font-size:9px;font-weight:800}.perf-status.degraded{background:#fff0dc;color:#9a5a00}.perf-status.critical{background:#ffe8eb;color:#a72939}.performance-foot button{height:29px;border:1px solid #c8dce6;border-radius:7px;background:#fff;color:#315d73;font-size:9px;font-weight:800;cursor:pointer}
body.dark .detail-drawer,body.theme-noc .detail-drawer,body.dark .performance-panel,body.theme-noc .performance-panel{background:#0c1e28;border-color:#31505f}body.dark .drawer-section,body.theme-noc .drawer-section,body.dark .performance-grid div,body.theme-noc .performance-grid div{background:#112a36;border-color:#294957}body.dark .detail-cell,body.theme-noc .detail-cell{background:#0b202b}body.dark .detail-cell b,body.theme-noc .detail-cell b,body.dark .drawer-section h4,body.theme-noc .drawer-section h4,body.dark .performance-grid b,body.theme-noc .performance-grid b{color:#e0f5fc}body.dark .health-ring-large:before,body.theme-noc .health-ring-large:before{background:#112a36}
@media(max-width:900px){.intel-strip{grid-template-columns:repeat(3,1fr)}}@media(max-width:600px){.performance-grid{grid-template-columns:repeat(2,1fr)}.detail-grid{grid-template-columns:1fr}.details-open{display:grid!important}}

/* ===== v43 3D Glass Bandwidth Engine ===== */
.chart{border:1px solid rgba(174,204,218,.75);background:linear-gradient(145deg,#ffffff 0%,#f5fbfd 56%,#e8f2f7 100%);box-shadow:inset 0 1px 0 rgba(255,255,255,.95),inset 0 -9px 18px rgba(43,92,117,.07),0 8px 18px rgba(22,64,85,.10);transform:perspective(1200px) rotateX(.35deg);transform-origin:center top}.card:hover .chart{box-shadow:inset 0 1px 0 rgba(255,255,255,.98),inset 0 -11px 22px rgba(43,92,117,.09),0 12px 25px rgba(22,64,85,.14)}.sw.rx{background:linear-gradient(180deg,#a8ffea 0%,#00d6a3 42%,#007a61 100%)!important;border:1px solid rgba(255,255,255,.7);box-shadow:0 2px 0 #006c56,0 3px 8px rgba(0,214,163,.48)!important}.sw.tx{background:linear-gradient(180deg,#d7d4ff 0%,#7168ff 42%,#3b2faf 100%)!important;border:1px solid rgba(255,255,255,.7);box-shadow:0 2px 0 #30258f,0 3px 8px rgba(108,99,255,.5)!important}.rxcur,.mini-rx{background:linear-gradient(180deg,#03dca9,#007a61);-webkit-background-clip:text;background-clip:text;color:transparent!important;text-shadow:0 1px 0 rgba(255,255,255,.45)}.txcur,.mini-tx{background:linear-gradient(180deg,#8d86ff,#3b2faf);-webkit-background-clip:text;background-clip:text;color:transparent!important;text-shadow:0 1px 0 rgba(255,255,255,.45)}body.dark .chart,body.theme-noc .chart{background:linear-gradient(145deg,#102935 0%,#0b1f29 55%,#07161e 100%);border-color:#2f5364;box-shadow:inset 0 1px 0 rgba(143,232,255,.12),inset 0 -12px 25px rgba(0,0,0,.28),0 9px 22px rgba(0,0,0,.28)}@media(prefers-reduced-motion:reduce){.chart{transform:none}}

/* ===== v44 Living Dashboard Visual System ===== */
body.visual-fx:after{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;background:radial-gradient(circle at 18% 15%,rgba(0,214,163,.07),transparent 28%),radial-gradient(circle at 82% 22%,rgba(108,99,255,.07),transparent 30%);animation:ambientField 10s ease-in-out infinite alternate}@keyframes ambientField{to{filter:hue-rotate(10deg);transform:scale(1.04)}}
body.visual-fx .topbar:after{content:"";position:absolute;left:-20%;bottom:0;width:35%;height:2px;background:linear-gradient(90deg,transparent,#55edff,transparent);animation:headerScan 4.8s linear infinite}@keyframes headerScan{to{left:110%}}
body.visual-fx .live-pill{animation:liveBreath 2.2s ease-in-out infinite}@keyframes liveBreath{50%{box-shadow:0 0 18px rgba(57,230,171,.22);border-color:rgba(80,232,184,.65)}}
body.visual-fx .health-ring{animation:healthFloat 2.8s ease-in-out infinite}@keyframes healthFloat{50%{transform:translateY(-2px);filter:drop-shadow(0 4px 7px rgba(0,214,163,.25))}}
body.visual-fx .kpi:before{animation:kpiFloat 3.4s ease-in-out infinite}body.visual-fx .kpi:nth-child(2):before{animation-delay:.2s}body.visual-fx .kpi:nth-child(3):before{animation-delay:.4s}body.visual-fx .kpi:nth-child(4):before{animation-delay:.6s}body.visual-fx .kpi:nth-child(5):before{animation-delay:.8s}body.visual-fx .kpi:nth-child(6):before{animation-delay:1s}@keyframes kpiFloat{50%{transform:translateY(-2px) scale(1.035)}}
.card{transition:transform .25s ease,box-shadow .25s ease,border-color .25s ease}.card:hover{transform:translateY(-4px) scale(1.003)}body.visual-fx .card.th-ok:before{background-size:220% 100%;animation:cardEnergy 4s linear infinite}body.visual-fx .card.th-warn:before{background:linear-gradient(90deg,#ff9f43,#ffe07b,#ff9f43);background-size:220% 100%;animation:cardEnergy 2.4s linear infinite}body.visual-fx .card.th-crit:before{background:linear-gradient(90deg,#e54858,#ff8995,#e54858);background-size:220% 100%;animation:cardEnergy 1.6s linear infinite}@keyframes cardEnergy{to{background-position:220% 0}}
.metric-strip .mini-metric{transition:transform .2s ease,box-shadow .2s ease}.metric-strip .mini-metric:hover{transform:translateY(-2px);box-shadow:0 7px 16px rgba(31,62,81,.11)}body.visual-fx .rx-metric:after{animation:metricOrb 3s ease-in-out infinite}body.visual-fx .tx-metric:after{animation:metricOrb 3s ease-in-out .55s infinite}body.visual-fx .util-metric:after{animation:metricOrb 3s ease-in-out 1.1s infinite}@keyframes metricOrb{50%{transform:translate(-8px,8px) scale(1.25);opacity:.14}}
.chart-stage{position:relative;margin:7px 8px 0}.chart-stage .chart{margin:0;width:100%;display:block}.zero-traffic-state{position:absolute;left:50%;top:58%;display:none;align-items:center;gap:11px;padding:8px 12px;border:1px solid rgba(122,157,174,.24);border-radius:12px;background:rgba(249,253,255,.66);color:#607b89;backdrop-filter:blur(7px);transform:translate(-50%,-50%);pointer-events:none}.card.zero-traffic .zero-traffic-state{display:flex}.zero-traffic-state strong{display:block;font-size:10px;letter-spacing:1px;color:#456574}.zero-traffic-state small{display:block;margin-top:2px;font-size:8px}.zero-radar{position:relative;width:31px;height:31px;display:block;border:1px solid rgba(0,185,141,.28);border-radius:50%}.zero-radar i{position:absolute;inset:5px;border:1px solid rgba(0,185,141,.25);border-radius:50%;animation:idleRadar 2.5s ease-out infinite}.zero-radar i:nth-child(2){animation-delay:1.25s}.zero-radar b{position:absolute;left:50%;top:50%;width:6px;height:6px;border-radius:50%;background:#00c892;box-shadow:0 0 9px rgba(0,200,146,.7);transform:translate(-50%,-50%)}@keyframes idleRadar{from{transform:scale(.35);opacity:1}to{transform:scale(1.45);opacity:0}}
.data-flow-particles{position:absolute;left:76px;right:76px;bottom:38px;height:12px;overflow:hidden;pointer-events:none;opacity:0}.card.has-traffic .data-flow-particles{opacity:.8}.data-flow-particles i{position:absolute;left:-15px;top:4px;width:7px;height:3px;border-radius:5px;background:#8cffe2;box-shadow:0 0 8px #00d6a3;animation:dataPacket 3.4s linear infinite}.data-flow-particles i:nth-child(2){animation-delay:.8s;background:#c9c5ff;box-shadow:0 0 8px #7168ff}.data-flow-particles i:nth-child(3){animation-delay:1.6s}.data-flow-particles i:nth-child(4){animation-delay:2.4s;background:#c9c5ff;box-shadow:0 0 8px #7168ff}@keyframes dataPacket{to{left:105%}}
body.visual-fx .card.has-traffic .mini-rx,body.visual-fx .card.has-traffic .mini-tx{animation:valuePulse 1.6s ease-in-out infinite alternate}@keyframes valuePulse{to{filter:brightness(1.22);letter-spacing:.25px}}
.card.status-down .badge{background:#ffe8eb;color:#b52739;box-shadow:0 0 0 1px rgba(229,72,88,.2)}body.visual-fx .card.status-down .badge{animation:downPulse 1.25s ease-in-out infinite}@keyframes downPulse{50%{box-shadow:0 0 0 6px rgba(229,72,88,0),0 0 14px rgba(229,72,88,.32)}}
body.visual-fx .chart-tooltip{animation:tooltipIn .14s ease-out}@keyframes tooltipIn{from{opacity:0;transform:translateY(5px)}}
body.dark .zero-traffic-state,body.theme-noc .zero-traffic-state{background:rgba(8,29,40,.72);border-color:#315462;color:#9cb6c1}body.dark .zero-traffic-state strong,body.theme-noc .zero-traffic-state strong{color:#d9eff7}
body.fx-low *,body.fx-low *:before,body.fx-low *:after{animation-duration:.001ms!important;animation-iteration-count:1!important}
@media(prefers-reduced-motion:reduce){body.visual-fx *,body.visual-fx *:before,body.visual-fx *:after{animation-duration:.001ms!important;animation-iteration-count:1!important}}

/* ===== v45 One Row RX/TX Bandwidth Chart ===== */
.chart-stage{margin-top:8px}.chart{transform:none!important;border:0!important;border-radius:12px!important;background:transparent!important;box-shadow:0 8px 22px rgba(22,64,85,.10)!important}.card:hover .chart{box-shadow:0 12px 27px rgba(22,64,85,.14)!important}.chart-tooltip{min-width:156px;border-radius:10px}.legend-table tr:nth-child(1) .name,.legend-table tr:nth-child(2) .name{font-weight:750}.metric-strip{grid-template-columns:minmax(0,1fr) minmax(0,1fr) minmax(0,.8fr) minmax(0,.8fr)}
@media(max-width:560px){.chart{height:220px!important}.metric-strip{grid-template-columns:1fr 1fr}.chart-stage{margin-left:5px;margin-right:5px}}


/* ===== v47 Eye Comfort Blue/Amber Thin Traffic Lines ===== */
:root{--rx:#2D8CFF;--rx-dark:#155BB5;--rx-soft:rgba(45,140,255,.12);--tx:#F59E0B;--tx-dark:#B86F00;--tx-soft:rgba(245,158,11,.12)}
.rxcur,.unitrx,.p95rx{color:#216FD1!important}.txcur,.unittx,.p95tx{color:#C87900!important}
.sw.rx{background:linear-gradient(90deg,#1769D2,#55A6FF)!important;box-shadow:0 0 5px rgba(45,140,255,.25)!important}
.sw.tx{background:linear-gradient(90deg,#B86F00,#FFB52E)!important;box-shadow:0 0 5px rgba(245,158,11,.25)!important}
.rxcur,.mini-rx{background:linear-gradient(180deg,#55A6FF,#155BB5);-webkit-background-clip:text;background-clip:text;color:transparent!important}
.txcur,.mini-tx{background:linear-gradient(180deg,#FFB52E,#B86F00);-webkit-background-clip:text;background-clip:text;color:transparent!important}


/* ===== v48 Reliable Dashboard Card Drag and Drop ===== */
.card-head{cursor:grab;touch-action:none;user-select:none}.card-head:active{cursor:grabbing}.card-head .tools,.card-head .tools *{touch-action:auto}.drag-hint{pointer-events:none;background:linear-gradient(135deg,#e8f4ff,#fff5df);border-color:#b9d2e5;color:#315d73}.card.drag-floating{position:fixed!important;z-index:30000!important;margin:0!important;pointer-events:none!important;opacity:.94;transform:rotate(.15deg) scale(1.01)!important;box-shadow:0 24px 60px rgba(10,36,52,.34)!important}.drag-ghost-placeholder{min-height:240px;border:2px dashed #2D8CFF!important;border-radius:17px;background:linear-gradient(135deg,rgba(45,140,255,.10),rgba(245,158,11,.08))!important;box-shadow:inset 0 0 0 4px rgba(255,255,255,.5)}body.card-drag-active{cursor:grabbing!important;user-select:none!important}body.card-drag-active .card:not(.dragging){transition:transform .12s ease,box-shadow .12s ease}.card-head .title:after{content:'  DRAG';margin-left:8px;padding:2px 5px;border-radius:5px;background:#e8f2fa;color:#698292;font-size:7px;vertical-align:2px;opacity:.65}.card:hover .card-head .title:after{opacity:1;color:#216fd1;background:#e4f0ff}
body.dark .card-head .title:after,body.theme-noc .card-head .title:after{background:#173544;color:#9bcde0}

</style></head><body class="role-<?=auth_is_admin()?'admin':'viewer'?>"><div id="userModal" class="user-modal" aria-hidden="true"><section class="user-dialog"><header class="user-dialog-head"><div><small>ADMINISTRATION</small><h2>User Management</h2></div><button type="button" id="closeUserModal">×</button></header><div class="user-create"><input id="newUsername" placeholder="Username"><input id="newFullName" placeholder="Nama lengkap"><input id="newPassword" type="password" placeholder="Password minimal 8 karakter"><select id="newRole"><option value="viewer">Viewer</option><option value="admin">Admin</option></select><button type="button" id="createUserBtn">Create User</button></div><div id="userList" class="user-list"></div><div id="userMessage" class="user-message">Admin dapat membuat Viewer dari halaman ini.</div></section></div><button id="exitTvBtn" class="exit-tv">Exit TV</button><div id="alertOverlay" class="alert-overlay"></div><aside id="detailDrawer" class="detail-drawer" aria-hidden="true"><div class="drawer-head"><div><small>INTERFACE OPERATIONS</small><h3 id="drawerTitle">Interface Detail</h3></div><button type="button" id="closeDetailDrawer">×</button></div><div id="drawerBody" class="drawer-body"></div></aside><div id="drawerBackdrop" class="drawer-backdrop"></div><section id="performancePanel" class="performance-panel" aria-hidden="true"><div class="performance-head"><div><small>BROWSER TELEMETRY</small><h3>Performance Monitor</h3></div><button type="button" id="closePerformancePanel">×</button></div><div class="performance-grid"><div><span>SUMMARY API</span><b id="perfSummary">--</b></div><div><span>PORTS API</span><b id="perfPorts">--</b></div><div><span>TOP TRAFFIC</span><b id="perfTop">--</b></div><div><span>LAST TICK</span><b id="perfTick">--</b></div><div><span>RENDER</span><b id="perfRender">--</b></div><div><span>FAILED REQUESTS</span><b id="perfErrors">0</b></div><div><span>ACTIVE REQUESTS</span><b id="perfActive">0</b></div><div><span>LOCAL STORAGE</span><b id="perfStorage">--</b></div></div><div class="performance-foot"><span id="perfStatus" class="perf-status">Collecting metrics...</span><button type="button" id="resetPerformanceMetrics">Reset Metrics</button></div></section><div id="incidentModal" class="incident-modal" aria-hidden="true"><div class="incident-dialog"><div class="incident-head"><div><small>PORT OPERATIONS</small><h3 id="incidentModalTitle">Incident Timeline</h3></div><button type="button" id="closeIncidentModal">×</button></div><div class="incident-summary"><span>Health <b id="modalHealthScore">100</b></span><span>Incidents <b id="modalIncidentCount">0</b></span><span>Downtime <b id="modalDowntime">0s</b></span></div><div id="incidentTimelineBody" class="incident-timeline-body"></div><div class="incident-foot"><button type="button" id="clearIncidentTimeline">Clear Timeline</button><button type="button" id="exportIncidentTimeline">Export JSON</button></div></div></div><button id="exitWidgetFullscreen" class="exit-widget-fullscreen">Exit Fullscreen</button><header class="topbar"><div class="brand-wrap"><div class="brand-icon server-rack-icon" title="LibreNMS Infrastructure Monitor" aria-label="LibreNMS Infrastructure Monitor"><svg viewBox="0 0 48 48" aria-hidden="true"><rect class="rack-frame" x="8" y="6" width="32" height="36" rx="6"/><rect class="rack-unit rack-unit-1" x="12" y="10" width="24" height="8" rx="2"/><rect class="rack-unit rack-unit-2" x="12" y="20" width="24" height="8" rx="2"/><rect class="rack-unit rack-unit-3" x="12" y="30" width="24" height="8" rx="2"/><circle class="rack-led led-1" cx="16" cy="14" r="1.8"/><circle class="rack-led led-2" cx="16" cy="24" r="1.8"/><circle class="rack-led led-3" cx="16" cy="34" r="1.8"/><path class="rack-slot" d="M21 14h10M21 24h10M21 34h10"/><path class="activity-wave" d="M5 25h5l3-6 4 12 4-13 4 8h5l3-5 3 4h7"/></svg></div><div><h1>Bandwidth Command Center</h1><p>LibreNMS DB <?=htmlspecialchars(DB_HOST)?> • Realtime Traffic Intelligence • History SSH/RRD</p></div></div><div class="header-right"><span class="live-pill"><i class="live-dot"></i> LIVE MONITORING</span><div class="clock" id="clock">-</div><div class="user-session"><strong><?=htmlspecialchars((string)(auth_user()['full_name']?:auth_user()['username']),ENT_QUOTES,'UTF-8')?></strong><span class="role-pill <?=auth_is_admin()?'admin':'viewer'?>"><?=strtoupper(htmlspecialchars((string)auth_user()['role'],ENT_QUOTES,'UTF-8'))?></span><button type="button" id="manageUsersBtn" class="user-manage-btn admin-only">Users</button><a class="logout-link" href="?action=logout">Logout</a></div></div></header>
<div class="viewer-notice">Mode Viewer aktif. Monitoring dan export tersedia, tetapi perubahan dashboard hanya dapat dilakukan oleh Admin.</div><section class="command-deck" aria-label="Dashboard command status">
  <div class="command-health"><span class="health-ring"><i></i></span><div><small>SYSTEM HEALTH</small><b id="systemHealthText">Connecting...</b></div></div>
  <div class="command-stat"><small>ACTIVE DASHBOARD</small><b id="activeDashboardLabel">Default</b></div>
  <div class="command-stat"><small>WIDGETS</small><b id="widgetCount">0 Ports</b></div>
  <div class="command-stat"><small>DATA MODE</small><b id="dataModeLabel">Live Stream</b></div>
  <div class="command-stat"><small>NEXT REFRESH</small><b id="refreshCountdown">--</b></div>
  <div class="command-actions"><button type="button" id="autoFitBtn" title="Automatically fit cards to current desktop width">Auto Fit</button><button type="button" id="densityBtn" title="Toggle compact dashboard">Compact</button><button type="button" id="focusBtn" title="Hide controls and focus on graphs">Focus</button><button type="button" id="performanceBtn" title="Open browser performance monitor">Performance</button><button type="button" id="visualFxBtn" title="Toggle ambient dashboard animation">Visual FX On</button><button type="button" id="rotateBtn" title="Auto rotate saved dashboard profiles">Rotate Off</button><button type="button" id="pinCriticalBtn" title="Move critical widgets to the top">Pin Critical</button><button type="button" id="pauseLiveBtn" title="Pause automatic live refresh">Pause Live</button><button type="button" id="manualRefreshBtn" title="Refresh dashboard now">Refresh</button></div>
</section>
<section class="summary"><div class="kpi"><b id="devTotal">0</b><span>Devices</span></div><div class="kpi good"><b id="devUp">0</b><span>Device UP</span></div><div class="kpi bad"><b id="devDown">0</b><span>Device DOWN</span></div><div class="kpi warn"><b id="alerts">0</b><span>Active Alerts</span></div><div class="kpi blue"><b id="rxTotal">0</b><span>Total RX Mbps</span></div><div class="kpi purple"><b id="txTotal">0</b><span>Total TX Mbps</span></div></section>
<div class="toolbar">
  <div class="toolbar-row main-search admin-only">
    <input id="search" placeholder="Cari host / wan1 / port1 / alias">
    <select id="portSelect"><option value="">Ketik cari port lalu pilih...</option></select>
    <button id="addBtn">Tambah Port</button>
  </div>
  <div class="toolbar-row actions">
    <select id="groupSelect" class="viewer-hidden-control"><option value="">Group...</option></select>
    <select id="themeSelect" class="viewer-hidden-control">
      <option value="light">Theme: Light</option>
      <option value="dark">Theme: Dark</option>
      <option value="noc">Theme: NOC</option>
      <option value="ocean">Theme: Ocean</option>
    </select>
    <button id="exportBtn" class="btn-export viewer-hidden-control">Export CSV</button>
    <button id="exportDocBtn" class="viewer-hidden-control">Export Gambar .DOC</button>
    <button id="exportChartBtn" class="viewer-hidden-control">Export CSV + Chart</button>
    <button id="tvBtn" class="btn-tv viewer-hidden-control">TV Mode</button>
    <button id="resetBtn" class="admin-only">Reset Browser</button>
    <button id="clearBtn" class="admin-only">Clear</button>
    <span id="saveStatus" class="save-status"></span>
  </div>
  <div class="toolbar-row profiles dashboard-profile-row">
    <span class="viewer-dashboard-label">VIEW DASHBOARD</span>
    <select id="profileSelect"><?=render_profile_options_server()?></select>
    <span id="viewerProfileStatus" class="viewer-profile-status">Pilih dashboard yang ingin dilihat</span>
    <input id="profileName" class="admin-only" placeholder="Nama dashboard, contoh: Branch / HO / DC">
    <button id="saveBtn" class="admin-only">Save Dashboard</button>
    <button id="saveAsBtn" class="admin-only">Save As</button>
    <button id="newDashboardBtn" class="admin-only">New Blank</button>
    <button id="deleteProfileBtn" class="btn-danger admin-only">Delete Dashboard</button>
  </div>
  <div class="range">Quick: <button data-range="live" class="active">Live</button><button data-range="5m">5m</button><button data-range="15m">15m</button><button data-range="30m">30m</button><button data-range="1h">1h</button><button data-range="3h">3h</button><button data-range="6h">6h</button><button data-range="12h">12h</button><button data-range="1d">1d</button><button data-range="7d">7d</button><button data-range="30d">30d</button></div>
  <div class="custom-time">Custom waktu: <input type="datetime-local" id="fromTime"> <span>s/d</span> <input type="datetime-local" id="toTime"> <button id="applyTime">Apply</button></div>
  <div class="chips" id="chips"></div>
</div>
<section class="top-panel" id="topPanel"><div class="topbox"><h3>Top RX</h3><div id="topRx"></div></div><div class="topbox"><h3>Top TX</h3><div id="topTx"></div></div><div class="topbox"><h3>Top Utilization</h3><div id="topUtil"></div></div></section><main><div class="grid" id="cards"></div></main><footer><span id="lastUpdate">Loading...</span></footer>
<script>
const userModal=document.getElementById('userModal'),userList=document.getElementById('userList'),userMessage=document.getElementById('userMessage');
function userMsg(text,error=false){if(!userMessage)return;userMessage.textContent=text;userMessage.classList.toggle('error',error)}
function userEsc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function userApi(api,payload){const opt=payload?{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF_TOKEN},body:JSON.stringify(payload)}:{cache:'no-store'};const r=await fetch('?api='+api,opt),j=await r.json();if(!r.ok||j.ok===false)throw new Error(j.error||('HTTP '+r.status));return j}
async function loadUsers(){if(!IS_ADMIN||!userList)return;userList.innerHTML='<div style="padding:25px;text-align:center">Loading users...</div>';try{const j=await userApi('users_list');userList.innerHTML='<div class="user-row header"><span>ID</span><span>USERNAME</span><span>FULL NAME</span><span>ROLE</span><span>STATUS</span><span>LAST LOGIN</span><span>ACTIONS</span></div>'+j.users.map(u=>`<div class="user-row" data-id="${u.id}"><b>${u.id}</b><span>${userEsc(u.username)}</span><input class="eu-name" value="${userEsc(u.full_name)}"><select class="eu-role"><option value="viewer" ${u.role==='viewer'?'selected':''}>Viewer</option><option value="admin" ${u.role==='admin'?'selected':''}>Admin</option></select><label class="user-status ${Number(u.is_active)?'on':'off'}"><input class="eu-active" type="checkbox" ${Number(u.is_active)?'checked':''}> ${Number(u.is_active)?'ACTIVE':'DISABLED'}</label><small>${userEsc(u.last_login||'Never')}</small><div class="user-actions"><button onclick="updateUser(${u.id})">Save</button><button onclick="resetUserPassword(${u.id},'${userEsc(u.username)}')">Reset Pass</button><button class="danger" onclick="deleteUser(${u.id},'${userEsc(u.username)}')">Delete</button></div></div>`).join('');userMsg(j.users.length+' user berhasil dimuat.')}catch(e){userList.innerHTML='';userMsg(e.message,true)}}
async function createUser(){const payload={username:newUsername.value.trim(),full_name:newFullName.value.trim(),password:newPassword.value,role:newRole.value};try{const j=await userApi('users_create',payload);newUsername.value='';newFullName.value='';newPassword.value='';newRole.value='viewer';userMsg(j.message);await loadUsers()}catch(e){userMsg(e.message,true)}}
async function updateUser(id){const row=userList.querySelector(`[data-id="${id}"]`);if(!row)return;try{const j=await userApi('users_update',{id,full_name:row.querySelector('.eu-name').value,role:row.querySelector('.eu-role').value,is_active:row.querySelector('.eu-active').checked});userMsg(j.message);await loadUsers()}catch(e){userMsg(e.message,true)}}
async function resetUserPassword(id,username){const password=prompt('Password baru untuk '+username+' (minimal 8 karakter):');if(password===null)return;try{const j=await userApi('users_reset_password',{id,password});userMsg(j.message)}catch(e){userMsg(e.message,true)}}
async function deleteUser(id,username){if(!confirm('Hapus user '+username+'?'))return;try{const j=await userApi('users_delete',{id});userMsg(j.message);await loadUsers()}catch(e){userMsg(e.message,true)}}
const AUTH_ROLE=<?=json_encode((string)auth_user()['role'])?>, IS_ADMIN=AUTH_ROLE==='admin', CSRF_TOKEN=<?=json_encode(auth_csrf())?>;
const REFRESH_MS=<?=REFRESH_SECONDS?>*1000, MAX_POINTS=80, DEFAULT_IDS=<?=json_encode(array_values(array_map('intval',$DEFAULT_PORT_IDS)))?>; function safePortIdsFromLocal(){try{const raw=localStorage.getItem('bw_selected_ports'); if(!raw)return DEFAULT_IDS; const arr=JSON.parse(raw); if(Array.isArray(arr))return arr.map(x=>Number(x)).filter(x=>x>0);}catch(e){console.warn('localStorage port corrupt, reset otomatis',e); localStorage.removeItem('bw_selected_ports');} return DEFAULT_IDS;} let selectedIds=safePortIdsFromLocal(); let currentProfile=localStorage.getItem('bw_profile')||''; let currentRange='live', customFrom='', customTo=''; let layoutDragging=false; const cardsEl=document.getElementById('cards'); const hist=new Map(); const meta=new Map(); let serverPortsLoaded=false;
async function persistIds(){localStorage.setItem('bw_selected_ports',JSON.stringify(selectedIds)); if(typeof saveStatus!=='undefined')saveStatus.textContent='saving...'; try{const r=await fetch('?api=save_ports',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF_TOKEN},body:JSON.stringify({ports:selectedIds})}); const j=await r.json(); if(!r.ok||j.ok===false)throw new Error(j.error||'save failed'); if(typeof saveStatus!=='undefined')saveStatus.textContent='saved '+selectedIds.length+' port'; return true;}catch(e){if(typeof saveStatus!=='undefined')saveStatus.textContent='save gagal: '+e.message; console.warn('save ports gagal',e); return false;}} function saveIds(){persistIds(); renderChips()} async function loadSavedIds(){if(currentProfile){return;} try{const local=safePortIdsFromLocal(); const r=await getJson('?api=load_ports'); if(Array.isArray(r.ports)&&r.ports.length){selectedIds=r.ports; localStorage.setItem('bw_selected_ports',JSON.stringify(selectedIds)); return;} if(Array.isArray(local)&&local.length){selectedIds=local; await persistIds(); return;}}catch(e){console.warn('load saved ports gagal',e); const local=safePortIdsFromLocal(); if(Array.isArray(local)&&local.length)selectedIds=local;}}
async function saveCurrentProfileSilent(){if(!currentProfile)return; try{await postJson('?api=profiles_save',{name:currentProfile,ports:selectedIds});}catch(e){console.warn('silent profile save gagal',e)}}
async function addSelectedPort(){if(!IS_ADMIN){alert('Role Viewer tidak boleh menambah port.');return;}const id=Number(portSelect.value); if(!id){saveStatus.textContent='pilih port dulu'; return;} if(!selectedIds.includes(id)){selectedIds.push(id);} localStorage.setItem('bw_selected_ports',JSON.stringify(selectedIds)); await persistIds(); await saveCurrentProfileSilent(); renderChips(); hist.clear(); saveStatus.textContent='added port '+id; await loadPorts();}
function esc(s){return String(s??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]))} function fmt(v){v=Number(v||0); if(v>=1000)return (v/1000).toFixed(2)+' Gbps'; if(v>=1)return v.toFixed(2)+' Mbps'; return (v*1000).toFixed(2)+' Kbps'} function fmtAxisUnit(v){v=Number(v||0); if(v>=1000)return (v/1000).toFixed(v>=10000?0:1)+' Gbps'; if(v>=1)return v.toFixed(v>=100?0:1)+' Mbps'; return (v*1000).toFixed(v*1000>=100?0:1)+' Kbps'} function avg(a){return a.length?a.reduce((x,y)=>x+y,0)/a.length:0} function max(a){return a.length?Math.max(...a):0} function p95(a){a=a.filter(x=>isFinite(x)).slice().sort((x,y)=>x-y); if(!a.length)return 0; const idx=.95*(a.length-1),lo=Math.floor(idx),hi=Math.ceil(idx); return lo===hi?a[lo]:a[lo]+(a[hi]-a[lo])*(idx-lo)} function nowLabel(){return new Date().toLocaleTimeString('id-ID',{hour:'2-digit',minute:'2-digit'})} function pad2(n){return String(n).padStart(2,'0')} function toLocalInput(d){return d.getFullYear()+'-'+pad2(d.getMonth()+1)+'-'+pad2(d.getDate())+'T'+pad2(d.getHours())+':'+pad2(d.getMinutes())} function fmtAxis(ts,span){const d=new Date(ts*1000); if(span>86400)return d.toLocaleDateString('id-ID',{day:'2-digit',month:'short'})+' '+d.toLocaleTimeString('id-ID',{hour:'2-digit',minute:'2-digit'}); return d.toLocaleTimeString('id-ID',{hour:'2-digit',minute:'2-digit'})} function initTime(){const to=new Date(), from=new Date(Date.now()-6*3600*1000); toTime.value=toLocalInput(to); fromTime.value=toLocalInput(from)} const perfMetrics={requests:{},active:0,errors:0,tick:0,render:0};function perfKey(url){if(url.includes('summary'))return'summary';if(url.includes('top_traffic'))return'top';if(url.includes('api=ports'))return'ports';if(url.includes('history'))return'history';return'other'}async function getJson(url){const started=performance.now(),key=perfKey(url);perfMetrics.active++;updatePerformanceUI();try{const r=await fetch(url,{cache:'no-store'});if(!r.ok)throw new Error(await r.text());const data=await r.json();perfMetrics.requests[key]=Math.round(performance.now()-started);return data}catch(e){perfMetrics.errors++;throw e}finally{perfMetrics.active--;updatePerformanceUI()}}
async function postJson(url,payload){
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF_TOKEN},body:JSON.stringify(payload||{})});
  const txt=await r.text();
  let j={}; try{j=txt?JSON.parse(txt):{};}catch(e){throw new Error('Response bukan JSON: '+txt.slice(0,180));}
  if(!r.ok || j.ok===false) throw new Error(j.error||('HTTP '+r.status));
  return j;
}
function selectedPortIdFromUi(){
  let id=Number(portSelect.value||0);
  if(!id){
    const first=[...portSelect.options].find(o=>Number(o.value)>0);
    if(first){ portSelect.value=first.value; id=Number(first.value); }
  }
  return id;
}
async function forceSaveSelectedPorts(){
  localStorage.setItem('bw_selected_ports',JSON.stringify(selectedIds));
  const saved=await postJson('?api=save_ports',{ports:selectedIds});
  if(currentProfile){ await postJson('?api=profiles_save',{name:currentProfile,ports:selectedIds}); }
  return saved;
}
async function addSelectedPort(){
  if(!IS_ADMIN){alert('Role Viewer tidak boleh menambah port.');return;}
  const id=selectedPortIdFromUi();
  if(!id){ saveStatus.textContent='pilih port dulu'; alert('Pilih port dulu dari dropdown hasil search, bre.'); return; }
  if(!selectedIds.includes(id)) selectedIds.push(id);
  selectedIds=[...new Set(selectedIds.map(Number).filter(x=>x>0))];
  hist.clear();
  cardsEl.querySelectorAll('.empty').forEach(e=>e.remove());
  saveStatus.textContent='adding port '+id+'...';
  try{
    const saved=await forceSaveSelectedPorts();
    renderChips();
    await loadPorts();
    saveStatus.textContent='added port '+id+' | total '+selectedIds.length;
    console.log('Add port saved', saved, selectedIds);
  }catch(e){
    saveStatus.textContent='add gagal: '+e.message;
    console.error('Add port gagal', e);
    alert('Add port gagal: '+e.message);
  }
}

function renderChips(){chips.innerHTML=''; selectedIds.forEach(id=>{const m=meta.get(id), name=m?m.title:'port_id '+id; const c=document.createElement('span'); c.className='chip'; c.innerHTML=esc(name)+` <a href="#" data-id="${id}">x</a>`; chips.appendChild(c)}); chips.querySelectorAll('a').forEach(a=>a.onclick=e=>{e.preventDefault(); selectedIds=selectedIds.filter(x=>x!=Number(a.dataset.id)); saveIds(); tick()})}
async function searchPorts(){const res=await getJson('?api=portlist&q='+encodeURIComponent(search.value.trim())); portSelect.innerHTML='<option value="">Pilih port...</option>'; (res.data||[]).forEach(p=>{const t=`${p.device_display||p.sysName||p.hostname||'-'} | IP:${p.device_ip||'-'} | ${p.ifName||p.ifDescr} | ${p.ifAlias||''} | id:${p.port_id} | RX:${p.rx_mbps} TX:${p.tx_mbps}`; const o=document.createElement('option'); o.value=p.port_id; o.textContent=t; portSelect.appendChild(o)})}
search.oninput=()=>{clearTimeout(window._st); window._st=setTimeout(searchPorts,350)}; addBtn.onclick=()=>{addSelectedPort()}; saveBtn.onclick=()=>{saveProfile(profileName.value||currentProfile||'Default');}; resetBtn.onclick=()=>{localStorage.removeItem('bw_selected_ports'); selectedIds=[]; persistIds(); renderChips(); tick();}; clearBtn.onclick=()=>{selectedIds=[]; saveIds(); tick()}; document.querySelectorAll('.range button').forEach(b=>b.onclick=()=>{document.querySelectorAll('.range button').forEach(x=>x.classList.remove('active')); b.classList.add('active'); currentRange=b.dataset.range; customFrom=''; customTo=''; hist.clear(); tick()}); applyTime.onclick=()=>{document.querySelectorAll('.range button').forEach(x=>x.classList.remove('active')); currentRange='custom'; customFrom=fromTime.value; customTo=toTime.value; hist.clear(); tick()};
function makeCard(item){meta.set(item.port_id,item); let id='port-'+item.port_id, card=document.getElementById(id); if(card){const title=card.querySelector('.title'); if(title){title.textContent=item.title; title.title=item.title;} const ipEl=card.querySelector('.ip-badge'); if(ipEl)ipEl.textContent='IP: '+(item.device_ip||'-'); const hostEl=card.querySelector('.host-label'); if(hostEl)hostEl.textContent='Device: '+(item.device_label||item.device_display||item.sysName||item.hostname||'-'); card.querySelectorAll('.legend-table .name').forEach((el,i)=>{if(i===0)el.innerHTML='<i class="sw rx"></i>'+esc(item.device_label||item.hostname)+': Interface '+esc(item.ifName)+': Bits received'; else if(i===1)el.innerHTML='<i class="sw tx"></i>'+esc(item.device_label||item.hostname)+': Interface '+esc(item.ifName)+': Bits sent'; else if(i===3)el.innerHTML='<i class="sw disc"></i>'+esc(item.device_label||item.hostname)+': Interface '+esc(item.ifName)+': Inbound packets discarded'; else if(i===4)el.innerHTML='<i class="sw err"></i>'+esc(item.device_label||item.hostname)+': Interface '+esc(item.ifName)+': Outbound packets with errors';}); return card;} card=document.createElement('div'); card.className='card'; card.id=id; applyCardSize(card,getCardSize(item.port_id)); applyCardDim(card,item.port_id); card.innerHTML=`<div class="card-head"><div class="title" title="${esc(item.title)}">${esc(item.title)}</div><div class="tools"><span class="size-tools"><button title="Small" onclick="setCardSize(${item.port_id},'s')">S</button><button title="Medium" onclick="setCardSize(${item.port_id},'m')">M</button><button title="Large" onclick="setCardSize(${item.port_id},'l')">L</button><button title="Wide" onclick="setCardSize(${item.port_id},'wide')">W</button><button title="Full width" onclick="setCardSize(${item.port_id},'full')">F</button></span><span class="layout-tools"><button title="Reset ukuran drag" onclick="resetCardDim(${item.port_id})">Reset Size</button></span><button onclick="removePort(${item.port_id})">✕</button> ⚙⋯ <span class="drag-hint" title="Drag pindah posisi">↕ Drag</span></div></div><div class="device-info"><span class="device-name-badge"><i></i><span class="host-label">Device: ${esc(item.device_label||item.device_display||item.sysName||item.hostname||'-')}</span></span><span class="ip-badge">IP ${esc(item.device_ip||'-')}</span><span class="iface-badge">IF ${esc(item.ifName||'-')}</span><span class="alias-badge" title="${esc(item.ifAlias||'No alias')}">${esc(item.ifAlias||'No alias')}</span></div><div class="metric-strip"><div class="mini-metric rx-metric"><span>LIVE RX</span><b class="mini-rx">0 Kbps</b></div><div class="mini-metric tx-metric"><span>LIVE TX</span><b class="mini-tx">0 Kbps</b></div><div class="mini-metric util-metric"><span>UTILIZATION</span><b class="mini-util">0%</b></div><div class="mini-metric speed-metric"><span>PORT SPEED</span><b>${item.speed_mbps?esc(item.speed_mbps+' Mbps'):'Unknown'}</b></div></div><div class="intel-strip"><span class="intel sla-intel" title="Availability observed during this dashboard session">SLA <b class="sla-value">100.000%</b></span><span class="intel anomaly-intel">ANOMALY <b class="anomaly-value">Normal</b></span><span class="intel forecast-intel">CAPACITY <b class="forecast-value">Learning</b></span><button type="button" class="health-score healthy" title="Port Health Score"><span>HEALTH</span><b class="health-score-value">100</b><i class="health-grade">Healthy</i></button><button type="button" class="timeline-open" title="Open incident timeline"><span>TIMELINE</span><b class="timeline-count">0</b><i>Events</i></button><button type="button" class="details-open" title="Open interface detail drawer"><span>DETAILS</span><b>›</b><i>Inspect</i></button></div><div class="chart-stage"><canvas class="chart"></canvas><div class="zero-traffic-state"><span class="zero-radar"><i></i><i></i><b></b></span><div><strong>LINK IDLE</strong><small>No bandwidth activity detected</small></div></div><div class="data-flow-particles" aria-hidden="true"><i></i><i></i><i></i><i></i></div></div><div class="graph-unit"><span class="unitrx">RX 0 Kbps</span> &nbsp; <span class="unittx">TX 0 Kbps</span></div><div class="chart-tooltip"></div><div class="resize-handle" title="Drag untuk resize"></div><table class="legend-table"><tbody><tr><td class="name"><i class="sw rx"></i>${esc(item.device_label||item.hostname)}: Interface ${esc(item.ifName)}: Bits received</td><td class="num rxcur">0</td><td class="num rxavg">0</td><td class="num rxmax">0</td></tr><tr><td class="name"><i class="sw tx"></i>${esc(item.device_label||item.hostname)}: Interface ${esc(item.ifName)}: Bits sent</td><td class="num txcur">0</td><td class="num txavg">0</td><td class="num txmax">0</td></tr><tr class="p95row"><td class="name">95th RX / TX percentile</td><td class="num p95rx">0</td><td class="num p95tx">0</td><td class="num"></td></tr><tr><td class="name"><i class="sw disc"></i>${esc(item.device_label||item.hostname)}: Interface ${esc(item.ifName)}: Inbound packets discarded</td><td class="num rxdisc">0</td><td class="num">0</td><td class="num">0</td></tr><tr><td class="name"><i class="sw err"></i>${esc(item.device_label||item.hostname)}: Interface ${esc(item.ifName)}: Outbound packets with errors</td><td class="num txerr">0</td><td class="num">0</td><td class="num">0</td></tr></tbody></table><span class="warnmsg"></span><div class="status"><span class="badge">UP</span> util <b class="util">0%</b></div>`; cardsEl.appendChild(card); hist.set(item.port_id,{t:[],rx:[],tx:[]}); const timelineBtn=card.querySelector('.timeline-open'),healthBtn=card.querySelector('.health-score'),detailsBtn=card.querySelector('.details-open');if(timelineBtn)timelineBtn.onclick=e=>{e.stopPropagation();renderIncidentModal(item.port_id)};if(healthBtn)healthBtn.onclick=e=>{e.stopPropagation();openDetailDrawer(item.port_id)};if(detailsBtn)detailsBtn.onclick=e=>{e.stopPropagation();openDetailDrawer(item.port_id)};card.addEventListener('dblclick',e=>{if(e.target.closest('button,.tools,.resize-handle'))return;document.body.classList.add('widget-fullscreen');card.classList.add('widget-expanded');setTimeout(()=>window.dispatchEvent(new Event('resize')),100)}); return card}

function sizeStoreKey(){return 'bw_card_sizes_'+(typeof currentProfile!=='undefined' && currentProfile ? currentProfile : 'default')}
function readCardSizes(){try{return JSON.parse(localStorage.getItem(sizeStoreKey())||'{}')||{}}catch(e){return {}}}
function writeCardSizes(s){localStorage.setItem(sizeStoreKey(),JSON.stringify(s||{}))}
function getCardSize(portId){const s=readCardSizes(); return s[portId]||'m'}
function applyCardSize(card,size){
  if(!card)return; ['size-s','size-m','size-l','size-xl','size-wide','size-full'].forEach(c=>card.classList.remove(c));
  card.classList.add('size-'+(size||'m'));
}
function setCardSize(portId,size){
  const s=readCardSizes(); s[portId]=size; writeCardSizes(s);
  const card=document.getElementById('port-'+portId); applyCardSize(card,size);
  setTimeout(()=>{const h=hist.get(portId); if(card&&h){const cv=card.querySelector('canvas'); draw(cv,h); attachTooltip(card,cv);}},80);
}


function dimStoreKey(){return 'bw_card_dims_'+(typeof currentProfile!=='undefined' && currentProfile ? currentProfile : 'default')}
function readCardDims(){try{return JSON.parse(localStorage.getItem(dimStoreKey())||'{}')||{}}catch(e){return {}}}
function writeCardDims(d){localStorage.setItem(dimStoreKey(),JSON.stringify(d||{}))}
function applyCardDim(card,portId){
  const d=readCardDims()[portId];
  if(d&&d.w&&d.h){card.classList.add('custom-dim');card.style.width=d.w+'px';card.style.height=d.h+'px';}
}
function saveCardDim(portId,card){
  const d=readCardDims();
  d[portId]={w:Math.round(card.getBoundingClientRect().width),h:Math.round(card.getBoundingClientRect().height)};
  writeCardDims(d);
}
function resetCardDim(portId){
  const d=readCardDims(); delete d[portId]; writeCardDims(d);
  const card=document.getElementById('port-'+portId); if(!card)return;
  card.classList.remove('custom-dim','resizing'); card.style.width=''; card.style.height='';
  const h=hist.get(portId); if(h){const cv=card.querySelector('canvas'); setTimeout(()=>{draw(cv,h); attachTooltip(card,cv);},60);}
}
function enableDragResize(card,portId){if(!IS_ADMIN)return;
  if(card._dragReady)return; card._dragReady=true;
  const handle=card.querySelector('.resize-handle'); if(!handle)return;
  let sx=0,sy=0,sw=0,sh=0,raf=null;
  function redraw(){const h=hist.get(portId); if(h){const cv=card.querySelector('canvas'); draw(cv,h); attachTooltip(card,cv);}}
  handle.addEventListener('mousedown',e=>{
    e.preventDefault(); e.stopPropagation(); card.classList.add('resizing','custom-dim');
    const r=card.getBoundingClientRect(); sx=e.clientX; sy=e.clientY; sw=r.width; sh=r.height;
    function move(ev){
      const nw=Math.max(360,sw+(ev.clientX-sx)); const nh=Math.max(300,sh+(ev.clientY-sy));
      card.style.width=nw+'px'; card.style.height=nh+'px';
      if(!raf)raf=requestAnimationFrame(()=>{raf=null; redraw();});
    }
    function up(){document.removeEventListener('mousemove',move);document.removeEventListener('mouseup',up);card.classList.remove('resizing'); saveCardDim(portId,card); redraw();}
    document.addEventListener('mousemove',move); document.addEventListener('mouseup',up);
  });
}


function orderStoreKey(){return 'bw_card_order_'+(typeof currentProfile!=='undefined' && currentProfile ? currentProfile : 'default')}
function readCardOrder(){try{return JSON.parse(localStorage.getItem(orderStoreKey())||'[]').map(Number).filter(x=>x>0)}catch(e){return []}}
function writeCardOrder(ids){localStorage.setItem(orderStoreKey(),JSON.stringify((ids||[]).map(Number).filter(x=>x>0)))}
function applySavedOrder(data){
  const order=readCardOrder(); if(!order.length)return data;
  const pos=new Map(order.map((id,i)=>[Number(id),i]));
  return data.slice().sort((a,b)=>(pos.has(a.port_id)?pos.get(a.port_id):999999)-(pos.has(b.port_id)?pos.get(b.port_id):999999));
}
function saveOrderFromDom(){
  selectedIds=[...document.querySelectorAll('.card')].map(c=>Number(c.id.replace('port-',''))).filter(x=>x>0);
  writeCardOrder(selectedIds);
  localStorage.setItem('bw_selected_ports',JSON.stringify(selectedIds));
  persistIds();
  // Save urutan ke profile aktif secara silent, jangan panggil saveProfile() supaya widget tidak reload/balik posisi.
  if(currentProfile){
    fetch('?api=profiles_save',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF_TOKEN},body:JSON.stringify({name:currentProfile,ports:selectedIds})}).catch(e=>console.warn('save order profile gagal',e));
  }
}
function enableDragMove(card,portId){if(!IS_ADMIN)return;
  if(card._moveReady)return; card._moveReady=true;
  const header=card.querySelector('.card-head');
  const grip=card.querySelector('.drag-hint');
  if(!header)return;
  let startX=0,startY=0,offX=0,offY=0,placeholder=null,dragging=false,pointerId=null;

  function movableCards(){return [...cardsEl.querySelectorAll('.card')].filter(c=>c!==card)}
  function closestCard(x,y){
    let best=null,score=Infinity;
    for(const c of movableCards()){
      const r=c.getBoundingClientRect(),cx=r.left+r.width/2,cy=r.top+r.height/2;
      const d=Math.hypot(x-cx,y-cy);
      if(d<score){score=d;best=c;}
    }
    return best;
  }
  function beginDrag(e){
    const r=card.getBoundingClientRect();
    placeholder=document.createElement('div');
    placeholder.className='drag-ghost-placeholder';
    placeholder.style.width=r.width+'px'; placeholder.style.height=r.height+'px';
    cardsEl.insertBefore(placeholder,card);
    document.body.appendChild(card);
    card.classList.add('drag-floating','dragging');
    card.style.width=r.width+'px'; card.style.height=r.height+'px';
    offX=e.clientX-r.left; offY=e.clientY-r.top;
    card.style.left=(e.clientX-offX)+'px'; card.style.top=(e.clientY-offY)+'px';
    layoutDragging=true; dragging=true;
    document.body.classList.add('card-drag-active');
  }
  function movePlaceholder(e){
    const target=closestCard(e.clientX,e.clientY); if(!target||!placeholder)return;
    const r=target.getBoundingClientRect();
    const sameRow=e.clientY>=r.top&&e.clientY<=r.bottom;
    const after=sameRow ? e.clientX>r.left+r.width/2 : e.clientY>r.top+r.height/2;
    cardsEl.insertBefore(placeholder,after?target.nextSibling:target);
  }
  function onPointerMove(e){
    if(pointerId!==null&&e.pointerId!==pointerId)return;
    const dx=Math.abs(e.clientX-startX),dy=Math.abs(e.clientY-startY);
    if(!dragging&&(dx>5||dy>5))beginDrag(e);
    if(!dragging)return;
    e.preventDefault();
    card.style.left=(e.clientX-offX)+'px'; card.style.top=(e.clientY-offY)+'px';
    movePlaceholder(e);
  }
  function finishDrag(){
    document.removeEventListener('pointermove',onPointerMove);
    document.removeEventListener('pointerup',onPointerUp);
    document.removeEventListener('pointercancel',onPointerUp);
    document.body.classList.remove('card-drag-active');
    if(dragging&&placeholder){
      cardsEl.insertBefore(card,placeholder); placeholder.remove();
      card.classList.remove('drag-floating','dragging');
      card.style.left=''; card.style.top=''; card.style.width=''; card.style.height='';
      applyCardDim(card,portId);
      layoutDragging=false; dragging=false;
      saveOrderFromDom();
      const h=hist.get(portId);if(h){const cv=card.querySelector('canvas');setTimeout(()=>{draw(cv,h);attachTooltip(card,cv)},80)}
      if(typeof saveStatus!=='undefined')saveStatus.textContent='posisi card tersimpan';
    }else layoutDragging=false;
    placeholder=null; pointerId=null;
  }
  function onPointerUp(e){if(pointerId!==null&&e.pointerId!==pointerId)return;finishDrag()}
  function onPointerDown(e){
    if(e.button!==0)return;
    // Tombol S/M/L/W/F, Reset, Close, Detail, dan resize tetap dapat diklik normal.
    if(e.target.closest('button,a,input,select,.size-tools,.layout-tools,.resize-handle'))return;
    e.preventDefault();
    pointerId=e.pointerId; startX=e.clientX; startY=e.clientY;
    document.addEventListener('pointermove',onPointerMove,{passive:false});
    document.addEventListener('pointerup',onPointerUp);
    document.addEventListener('pointercancel',onPointerUp);
  }
  header.addEventListener('pointerdown',onPointerDown);
  if(grip){grip.title='Tahan dan geser untuk memindahkan card';grip.textContent='↕ Drag';}
}
function removePort(id){if(!IS_ADMIN){alert('Role Viewer tidak boleh menghapus port.');return;}selectedIds=selectedIds.filter(x=>x!==id); saveIds(); tick()}
function draw(canvas,h){
  const rect=canvas.getBoundingClientRect(),dpr=window.devicePixelRatio||1;
  const w=Math.max(320,rect.width),cssH=Math.max(190,rect.height||260);
  canvas.width=Math.floor(w*dpr); canvas.height=Math.floor(cssH*dpr);
  const ctx=canvas.getContext('2d'); ctx.setTransform(dpr,0,0,dpr,0,0); ctx.clearRect(0,0,w,cssH);

  // Libre-style one-row RX/TX chart with independent left/right scales.
  const compact=w<560, L=compact?58:70, R=compact?58:70, T=compact?54:58, B=34;
  const plotW=Math.max(80,w-L-R),plotH=Math.max(70,cssH-T-B);
  const rx=(h.rx||[]).map(Number),tx=(h.tx||[]).map(Number),labels=(h.t||[]).slice();
  const niceMax=v=>{v=Math.max(0,Number(v)||0);if(v<=0)return 1;const raw=v*1.16,p=Math.pow(10,Math.floor(Math.log10(raw))),n=raw/p;return (n<=1?1:n<=2?2:n<=2.5?2.5:n<=5?5:10)*p};
  const rxMax=max(rx),txMax=max(tx),yMax=niceMax(Math.max(rxMax,txMax));
  const dark=document.body.classList.contains('dark')||document.body.classList.contains('theme-noc');
  const C={panel:dark?'#0b202b':'#f8fcfe',plot:dark?'#0c2632':'#ffffff',grid:dark?'rgba(110,160,181,.20)':'rgba(95,135,155,.17)',text:dark?'#b6cdd8':'#627987',border:dark?'#315262':'#d9e7ee',rx:'#2D8CFF',tx:'#F59E0B'};

  // Rounded chart shell.
  ctx.save();ctx.beginPath();if(ctx.roundRect)ctx.roundRect(.5,.5,w-1,cssH-1,12);else ctx.rect(.5,.5,w-1,cssH-1);ctx.clip();
  const shell=ctx.createLinearGradient(0,0,0,cssH);shell.addColorStop(0,C.panel);shell.addColorStop(1,dark?'#081a23':'#eef7fb');ctx.fillStyle=shell;ctx.fillRect(0,0,w,cssH);
  ctx.fillStyle=C.plot;ctx.fillRect(L,T,plotW,plotH);

  // Single-row header: RX, TX, peaks, and both scale captions.
  ctx.font='800 10px Arial';ctx.textBaseline='middle';
  ctx.fillStyle=C.text;ctx.fillText('BANDWIDTH SCALE',L,13);
  ctx.textAlign='right';ctx.fillText('RX + TX  |  Mbps',L+plotW,13);ctx.textAlign='left';
  function headerPill(x,color,label,value){
    const text=label+'  '+value,tw=ctx.measureText(text).width,pw=tw+28;
    ctx.fillStyle=dark?'rgba(15,43,56,.94)':'rgba(255,255,255,.95)';ctx.strokeStyle=color+'55';ctx.lineWidth=1;
    ctx.beginPath();if(ctx.roundRect)ctx.roundRect(x,22,pw,24,12);else ctx.rect(x,22,pw,24);ctx.fill();ctx.stroke();
    ctx.fillStyle=color;ctx.beginPath();ctx.arc(x+11,34,3.5,0,Math.PI*2);ctx.fill();ctx.fillStyle=dark?'#e1f3fa':'#29495a';ctx.fillText(text,x+20,34);return pw;
  }
  let hx=L;hx+=headerPill(hx,C.rx,'RX',fmt(rx.length?rx[rx.length-1]:0))+6;
  if(hx<L+plotW-110)hx+=headerPill(hx,C.tx,'TX',fmt(tx.length?tx[tx.length-1]:0))+6;
  if(!compact&&hx<L+plotW-175){
    hx+=headerPill(hx,C.rx,'PEAK RX',fmt(rxMax))+6;
    if(hx<L+plotW-155)headerPill(hx,C.tx,'PEAK TX',fmt(txMax));
  }

  // Grid and dual labels.
  ctx.font=(compact?'700 9px':'700 10px')+' Arial';ctx.textBaseline='middle';
  for(let i=0;i<=4;i++){
    const y=T+plotH*i/4;ctx.strokeStyle=i===4?C.border:C.grid;ctx.lineWidth=i===4?1.2:1;ctx.setLineDash(i===4?[]:[3,4]);ctx.beginPath();ctx.moveTo(L,y);ctx.lineTo(L+plotW,y);ctx.stroke();
    ctx.setLineDash([]);ctx.textAlign='right';ctx.fillStyle=C.text;ctx.fillText(fmtAxisUnit(yMax*(1-i/4)),L-7,y);
  }
  for(let i=0;i<=6;i++){const x=L+plotW*i/6;ctx.strokeStyle=C.grid;ctx.setLineDash([3,4]);ctx.beginPath();ctx.moveTo(x,T);ctx.lineTo(x,T+plotH);ctx.stroke()}ctx.setLineDash([]);

  const point=(arr,i,scale)=>[L+plotW*i/Math.max(1,arr.length-1),T+plotH-(Math.max(0,arr[i]||0)/scale)*plotH];
  function path(arr,scale){if(!arr.length)return;const p=arr.map((_,i)=>point(arr,i,scale));ctx.beginPath();ctx.moveTo(...p[0]);for(let i=1;i<p.length;i++){const prev=p[i-1],cur=p[i],mx=(prev[0]+cur[0])/2;ctx.bezierCurveTo(mx,prev[1],mx,cur[1],cur[0],cur[1])}}
  function series(arr,scale,color,deep,fill){
    if(!arr.length)return;
    path(arr,scale);const last=point(arr,arr.length-1,scale);ctx.lineTo(last[0],T+plotH);ctx.lineTo(L,T+plotH);ctx.closePath();const g=ctx.createLinearGradient(0,T,0,T+plotH);g.addColorStop(0,fill);g.addColorStop(1,'rgba(255,255,255,0)');ctx.fillStyle=g;ctx.fill();
    ctx.save();ctx.lineCap='round';ctx.lineJoin='round';ctx.shadowColor=color;ctx.shadowBlur=5;ctx.strokeStyle=deep;ctx.lineWidth=3.4;path(arr,scale);ctx.stroke();ctx.shadowBlur=3;ctx.strokeStyle=color;ctx.lineWidth=2.15;path(arr,scale);ctx.stroke();ctx.shadowBlur=0;ctx.globalAlpha=.75;ctx.strokeStyle='#ffffff';ctx.lineWidth=.65;ctx.translate(0,-.55);path(arr,scale);ctx.stroke();ctx.restore();
    const [x,y]=last;ctx.save();ctx.shadowColor=color;ctx.shadowBlur=5;ctx.fillStyle='#fff';ctx.beginPath();ctx.arc(x,y,3.4,0,Math.PI*2);ctx.fill();ctx.lineWidth=1.7;ctx.strokeStyle=color;ctx.stroke();ctx.restore();
  }
  // TX first, RX second so both remain readable when lines overlap.
  series(tx,yMax,C.tx,'#B86F00','rgba(245,158,11,.11)');
  series(rx,yMax,C.rx,'#155BB5','rgba(45,140,255,.12)');

  // Time labels.
  ctx.font='700 9px Arial';ctx.fillStyle=C.text;ctx.textBaseline='alphabetic';
  if(labels.length){const mid=Math.floor(labels.length/2);ctx.textAlign='left';ctx.fillText(labels[0],L,T+plotH+22);ctx.textAlign='center';ctx.fillText(labels[mid],L+plotW/2,T+plotH+22);ctx.textAlign='right';ctx.fillText(labels[labels.length-1],L+plotW,T+plotH+22)}
  ctx.restore();ctx.strokeStyle=C.border;ctx.lineWidth=1;ctx.beginPath();if(ctx.roundRect)ctx.roundRect(.5,.5,w-1,cssH-1,12);else ctx.rect(.5,.5,w-1,cssH-1);ctx.stroke();
  canvas._chartMeta={L,R,T,B,plotW,plotH,yMax,yMaxRx:yMax,yMaxTx:yMax,labels,rx:rx.slice(),tx:tx.slice()};
}
function attachTooltip(card,canvas){
  if(canvas._tipReady)return; canvas._tipReady=true;
  const tip=card.querySelector('.chart-tooltip'); if(!tip)return;
  canvas.addEventListener('mousemove',ev=>{
    const m=canvas._chartMeta; if(!m||!m.rx.length)return;
    const r=canvas.getBoundingClientRect(); const x=ev.clientX-r.left, y=ev.clientY-r.top;
    if(x<m.L||x>m.L+m.plotW||y<m.T||y>m.T+m.plotH){card.classList.remove('hovering');return;}
    const idx=Math.max(0,Math.min(m.rx.length-1,Math.round((x-m.L)/m.plotW*(m.rx.length-1))));
    const px=m.L+m.plotW*idx/Math.max(1,m.rx.length-1);
    const rxScale=m.yMaxRx||m.yMax||1, txScale=m.yMaxTx||m.yMax||1;
    const rxY=m.T+m.plotH-(m.rx[idx]/rxScale*m.plotH), txY=m.T+m.plotH-(m.tx[idx]/txScale*m.plotH);
    const ctx=canvas.getContext('2d'); draw(canvas,{t:m.labels,rx:m.rx,tx:m.tx});
    ctx.save(); ctx.setLineDash([3,3]); ctx.strokeStyle='rgba(40,60,75,.75)'; ctx.beginPath(); ctx.moveTo(px,m.T); ctx.lineTo(px,m.T+m.plotH); ctx.stroke(); ctx.setLineDash([]);
    [[rxY,'#2D8CFF'],[txY,'#F59E0B']].forEach(([py,c])=>{ctx.beginPath();ctx.arc(px,py,5,0,Math.PI*2);ctx.fillStyle='#fff';ctx.fill();ctx.lineWidth=2;ctx.strokeStyle=c;ctx.stroke();}); ctx.restore();
    tip.innerHTML='<div><b>'+esc(m.labels[idx]||'')+'</b></div><div>RX: <b>'+fmt(m.rx[idx])+'</b> <small>(skala Mbps sama)</small></div><div>TX: <span class="txv">'+fmt(m.tx[idx])+'</span> <small>(skala Mbps sama)</small></div>';
    tip.style.left=(Math.min(card.clientWidth-170,Math.max(10,x+18)))+'px'; tip.style.top=(Math.max(44,y-10))+'px'; card.classList.add('hovering');
  });
  canvas.addEventListener('mouseleave',()=>{card.classList.remove('hovering'); const m=canvas._chartMeta; if(m)draw(canvas,{t:m.labels,rx:m.rx,tx:m.tx});});
}

const slaSession=new Map(),alertMemory=new Map();let pinCriticalEnabled=localStorage.getItem('bw_pin_critical')==='1',rotateTimer=null;
function linearForecast(arr,steps=12){const v=(arr||[]).slice(-30).map(Number).filter(Number.isFinite);if(v.length<6)return null;const n=v.length,sx=n*(n-1)/2,sy=v.reduce((a,b)=>a+b,0),sxx=(n-1)*n*(2*n-1)/6,sxy=v.reduce((a,y,x)=>a+x*y,0),den=n*sxx-sx*sx;if(!den)return null;const slope=(n*sxy-sx*sy)/den,inter=(sy-slope*sx)/n;return Math.max(0,inter+slope*(n-1+steps))}
function anomalyScore(arr,current){const v=(arr||[]).slice(-25,-1).map(Number).filter(Number.isFinite);if(v.length<8)return 0;const mean=v.reduce((a,b)=>a+b,0)/v.length,sd=Math.sqrt(v.reduce((a,b)=>a+(b-mean)**2,0)/v.length);return sd>0?Math.abs(Number(current)-mean)/sd:0}
function showNocAlert(item,type,message){const key=item.port_id+':'+type,now=Date.now();if(now-(alertMemory.get(key)||0)<60000)return;alertMemory.set(key,now);const box=document.getElementById('alertOverlay');if(!box)return;const el=document.createElement('div');el.className='noc-alert '+(type==='warning'?'warn':'');el.innerHTML='<span class="alert-icon">'+(type==='down'?'DN':'!')+'</span><div><b>'+esc(item.device_label||item.hostname)+' - '+esc(item.ifName)+'</b><small>'+esc(message)+'</small></div><button type="button">×</button>';el.querySelector('button').onclick=()=>el.remove();box.prepend(el);setTimeout(()=>el.remove(),12000)}
const incidentStore=new Map(),portStateStore=new Map();let activeIncidentPortId=0;
function incidentStorageKey(id){return 'bw_incident_timeline_'+Number(id)}
function loadIncidentTimeline(id){if(incidentStore.has(id))return incidentStore.get(id);let rows=[];try{rows=JSON.parse(localStorage.getItem(incidentStorageKey(id))||'[]');if(!Array.isArray(rows))rows=[]}catch(e){rows=[]}rows=rows.slice(-60);incidentStore.set(id,rows);return rows}
function saveIncidentTimeline(id,rows){const clean=(rows||[]).slice(-60);incidentStore.set(id,clean);localStorage.setItem(incidentStorageKey(id),JSON.stringify(clean))}
function formatDurationMs(ms){ms=Math.max(0,Number(ms)||0);const sec=Math.floor(ms/1000),d=Math.floor(sec/86400),h=Math.floor(sec%86400/3600),m=Math.floor(sec%3600/60),s=sec%60;if(d)return d+'d '+h+'h';if(h)return h+'h '+m+'m';if(m)return m+'m '+s+'s';return s+'s'}
function pushIncident(id,type,severity,title,message,value){const rows=loadIncidentTimeline(id),last=rows[rows.length-1],now=Date.now();if(last&&last.type===type&&last.value===value&&now-last.ts<60000)return;rows.push({ts:now,type,severity,title,message,value:value??'',resolved:false,duration:0});saveIncidentTimeline(id,rows);updateTimelineCount(id)}
function resolveIncident(id,type,title,message){const rows=loadIncidentTimeline(id),now=Date.now();for(let i=rows.length-1;i>=0;i--){if(rows[i].type===type&&!rows[i].resolved){rows[i].resolved=true;rows[i].resolvedAt=now;rows[i].duration=now-rows[i].ts;rows.push({ts:now,type:type+'_recovery',severity:'recovery',title,message,duration:rows[i].duration,resolved:true});saveIncidentTimeline(id,rows);updateTimelineCount(id);return}}}
function activeIncidentCount(id){return loadIncidentTimeline(id).filter(x=>!x.resolved&&['down','util-warning','util-critical','error','discard','anomaly'].includes(x.type)).length}
function updateTimelineCount(id){const card=document.getElementById('port-'+id),el=card&&card.querySelector('.timeline-count');if(el)el.textContent=loadIncidentTimeline(id).length}
function healthBreakdown(item,h,sla,z){const status=String(item.status||'up').toLowerCase(),util=Number(item.util_pct||0),err=Number(item.rxerr||0)+Number(item.txerr||0),disc=Number(item.rxdisc||0)+Number(item.txdisc||0),rows=[{label:'Base health',points:100}];if(status!=='up')rows.push({label:'Interface '+status.toUpperCase(),points:-55});if(util>=95)rows.push({label:'Utilization ≥95%',points:-25});else if(util>=85)rows.push({label:'Utilization ≥85%',points:-18});else if(util>=65)rows.push({label:'Utilization ≥65%',points:-8});if(err>100)rows.push({label:'High interface errors',points:-18});else if(err>10)rows.push({label:'Interface errors',points:-10});else if(err>0)rows.push({label:'Minor errors',points:-4});if(disc>100)rows.push({label:'High packet discards',points:-13});else if(disc>10)rows.push({label:'Packet discards',points:-7});else if(disc>0)rows.push({label:'Minor discards',points:-3});if(z>=4)rows.push({label:'Critical anomaly',points:-12});else if(z>=2.7)rows.push({label:'Traffic anomaly',points:-6});if(sla<99)rows.push({label:'SLA below 99%',points:-10});else if(sla<99.9)rows.push({label:'SLA below 99.9%',points:-5});const recent=[...(h.rx||[]),...(h.tx||[])].slice(-30).map(Number).filter(Number.isFinite);if(recent.length>8){const mean=recent.reduce((a,b)=>a+b,0)/recent.length,sd=Math.sqrt(recent.reduce((a,b)=>a+(b-mean)**2,0)/recent.length);if(mean>0&&sd/mean>1.2)rows.push({label:'Traffic instability',points:-4})}const score=Math.max(0,Math.min(100,Math.round(rows.reduce((a,x)=>a+x.points,0))));return{score,rows,status,util,err,disc,sla,z}}
function calculateHealthScore(item,h,sla,z){return healthBreakdown(item,h,sla,z).score}

let activeDetailPortId=0;function storageSizeKb(){let bytes=0;try{for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i)||'';bytes+=k.length+(localStorage.getItem(k)||'').length}}catch(e){}return(bytes*2/1024).toFixed(1)+' KB'}function updatePerformanceUI(){const set=(id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v};set('perfSummary',(perfMetrics.requests.summary??'--')+(perfMetrics.requests.summary!=null?' ms':''));set('perfPorts',(perfMetrics.requests.ports??'--')+(perfMetrics.requests.ports!=null?' ms':''));set('perfTop',(perfMetrics.requests.top??'--')+(perfMetrics.requests.top!=null?' ms':''));set('perfTick',perfMetrics.tick?perfMetrics.tick+' ms':'--');set('perfRender',perfMetrics.render?perfMetrics.render+' ms':'--');set('perfErrors',perfMetrics.errors);set('perfActive',perfMetrics.active);set('perfStorage',storageSizeKb());const vals=[perfMetrics.requests.summary,perfMetrics.requests.ports,perfMetrics.tick].filter(Number.isFinite),worst=vals.length?Math.max(...vals):0,status=document.getElementById('perfStatus');if(status){status.classList.remove('degraded','critical');if(perfMetrics.errors>0||worst>3000){status.textContent='CRITICAL - check API or browser';status.classList.add('critical')}else if(worst>1200){status.textContent='DEGRADED - response is slower';status.classList.add('degraded')}else status.textContent=worst?'HEALTHY - '+worst+' ms worst':'Collecting metrics...'}}function openDetailDrawer(id){const item=meta.get(id);if(!item)return;activeDetailPortId=id;const card=document.getElementById('port-'+id),h=hist.get(id)||{rx:[],tx:[]},slaRec=slaSession.get(id)||{checks:0,up:0},sla=slaRec.checks?slaRec.up/slaRec.checks*100:100,z=Math.max(anomalyScore(h.rx,item.rx_mbps),anomalyScore(h.tx,item.tx_mbps)),health=healthBreakdown(item,h,sla,z),rows=loadIncidentTimeline(id),active=rows.filter(x=>!x.resolved).slice(-5).reverse();document.getElementById('drawerTitle').textContent=(item.device_label||item.hostname||'Device')+' - '+(item.ifName||'Interface');document.getElementById('drawerBody').innerHTML='<section class="drawer-section"><h4>INTERFACE IDENTITY</h4><div class="detail-grid">'+[['Device',item.device_label||item.hostname],['IP Address',item.device_ip||'-'],['Interface',item.ifName||'-'],['Alias',item.ifAlias||'-'],['Port ID',item.port_id],['Port Speed',item.speed_mbps?item.speed_mbps+' Mbps':'Unknown'],['Status',String(item.status||'up').toUpperCase()],['Utilization',Number(item.util_pct||0).toFixed(1)+'%']].map(x=>'<div class="detail-cell"><span>'+esc(x[0])+'</span><b>'+esc(x[1])+'</b></div>').join('')+'</div></section><section class="drawer-section"><h4>TRAFFIC TELEMETRY</h4><div class="detail-grid">'+[['Current RX',fmt(item.rx_mbps)],['Current TX',fmt(item.tx_mbps)],['Average RX',fmt(avg(h.rx))],['Average TX',fmt(avg(h.tx))],['Peak RX',fmt(max(h.rx))],['Peak TX',fmt(max(h.tx))],['Errors',health.err.toFixed(2)],['Discards',health.disc.toFixed(2)]].map(x=>'<div class="detail-cell"><span>'+esc(x[0])+'</span><b>'+esc(x[1])+'</b></div>').join('')+'</div></section><section class="drawer-section"><h4>HEALTH SCORE BREAKDOWN</h4><div class="health-ring-large" style="--score:'+health.score+'"><strong>'+health.score+'</strong><small>'+((health.score>=90)?'Healthy':health.score>=70?'Degraded':'Critical')+'</small></div>'+health.rows.map(x=>'<div class="breakdown-row"><span>'+esc(x.label)+'</span><b class="'+(x.points<0?'penalty':'good-points')+'">'+(x.points>0?'+':'')+x.points+'</b></div>').join('')+'</section><section class="drawer-section"><h4>ACTIVE INCIDENTS</h4><div class="drawer-incidents">'+(active.length?active.map(x=>'<div class="drawer-incident '+(x.severity==='critical'?'critical':'')+'"><b>'+esc(x.title||x.type)+'</b><br>'+esc(x.message||'')+'</div>').join(''):'<div class="timeline-empty">No active incidents.</div>')+'</div></section>';document.getElementById('detailDrawer').classList.add('open');document.getElementById('drawerBackdrop').classList.add('open');document.getElementById('detailDrawer').setAttribute('aria-hidden','false')}function closeDetailDrawer(){document.getElementById('detailDrawer').classList.remove('open');document.getElementById('drawerBackdrop').classList.remove('open');document.getElementById('detailDrawer').setAttribute('aria-hidden','true')}
function updateHealthUI(card,score){const box=card.querySelector('.health-score'),val=card.querySelector('.health-score-value'),grade=card.querySelector('.health-grade');const cls=score>=90?'healthy':score>=70?'degraded':'critical',label=score>=90?'Healthy':score>=70?'Degraded':'Critical';if(box){box.classList.remove('healthy','degraded','critical');box.classList.add(cls)}if(val)val.textContent=score;if(grade)grade.textContent=label;card.classList.remove('health-degraded','health-critical');if(cls==='degraded')card.classList.add('health-degraded');if(cls==='critical')card.classList.add('health-critical');card.dataset.healthScore=score}
function trackPortIncidents(item,z){const id=Number(item.port_id),now={status:String(item.status||'up').toLowerCase(),util:Number(item.util_pct||0),err:Number(item.rxerr||0)+Number(item.txerr||0),disc:Number(item.rxdisc||0)+Number(item.txdisc||0),anomaly:z>=4},prev=portStateStore.get(id);if(!prev){portStateStore.set(id,now);if(now.status!=='up')pushIncident(id,'down','critical','Interface Down','Initial state detected as '+now.status.toUpperCase(),now.status);if(now.util>=85)pushIncident(id,'util-critical','critical','Critical Utilization','Utilization reached '+now.util.toFixed(1)+'%',Math.round(now.util));return}if(prev.status==='up'&&now.status!=='up')pushIncident(id,'down','critical','Interface Down','Status changed from UP to '+now.status.toUpperCase(),now.status);if(prev.status!=='up'&&now.status==='up')resolveIncident(id,'down','Interface Recovered','Status returned to UP');if(prev.util<85&&now.util>=85)pushIncident(id,'util-critical','critical','Critical Utilization','Utilization crossed 85% at '+now.util.toFixed(1)+'%',Math.round(now.util));if(prev.util>=85&&now.util<85)resolveIncident(id,'util-critical','Utilization Recovered','Utilization returned below 85% at '+now.util.toFixed(1)+'%');if(prev.util<65&&now.util>=65&&now.util<85)pushIncident(id,'util-warning','warning','High Utilization','Utilization crossed 65% at '+now.util.toFixed(1)+'%',Math.round(now.util));if(prev.util>=65&&now.util<65)resolveIncident(id,'util-warning','Utilization Normal','Utilization returned below 65% at '+now.util.toFixed(1)+'%');if(prev.err<=0&&now.err>0)pushIncident(id,'error','warning','Interface Errors','Error rate detected: '+now.err.toFixed(2),Math.round(now.err));if(prev.err>0&&now.err<=0)resolveIncident(id,'error','Errors Cleared','Interface error rate returned to zero');if(prev.disc<=0&&now.disc>0)pushIncident(id,'discard','warning','Packet Discards','Discard rate detected: '+now.disc.toFixed(2),Math.round(now.disc));if(prev.disc>0&&now.disc<=0)resolveIncident(id,'discard','Discards Cleared','Packet discard rate returned to zero');if(!prev.anomaly&&now.anomaly)pushIncident(id,'anomaly','warning','Traffic Anomaly','Traffic deviation reached '+z.toFixed(1)+' standard deviations',z.toFixed(1));if(prev.anomaly&&!now.anomaly)resolveIncident(id,'anomaly','Traffic Normalized','Traffic pattern returned to normal');portStateStore.set(id,now)}
function renderIncidentModal(id){const rows=loadIncidentTimeline(id).slice().reverse(),item=meta.get(id)||{},body=document.getElementById('incidentTimelineBody');activeIncidentPortId=id;document.getElementById('incidentModalTitle').textContent=(item.device_label||item.hostname||'Port')+' - '+(item.ifName||id);document.getElementById('modalHealthScore').textContent=document.getElementById('port-'+id)?.dataset.healthScore||100;document.getElementById('modalIncidentCount').textContent=rows.length;document.getElementById('modalDowntime').textContent=formatDurationMs(rows.filter(x=>x.type==='down').reduce((a,x)=>a+(x.duration||(!x.resolved?Date.now()-x.ts:0)),0));body.innerHTML=rows.length?rows.map(x=>'<div class="timeline-event '+esc(x.severity||'')+'"><div class="timeline-event-head"><b>'+esc(x.title||x.type)+'</b><time>'+new Date(x.ts).toLocaleString('id-ID')+'</time></div><p>'+esc(x.message||'')+'</p><small>'+(x.duration?'Duration '+formatDurationMs(x.duration):x.resolved?'Resolved':'Active incident')+'</small></div>').join(''):'<div class="timeline-empty">Belum ada incident pada port ini.</div>';const modal=document.getElementById('incidentModal');modal.classList.add('open');modal.setAttribute('aria-hidden','false')}
function closeIncident(){const modal=document.getElementById('incidentModal');modal.classList.remove('open');modal.setAttribute('aria-hidden','true')}
function updateIntelligence(card,item,h){const id=Number(item.port_id),status=String(item.status||'up').toLowerCase(),rec=slaSession.get(id)||{checks:0,up:0};rec.checks++;if(status==='up')rec.up++;slaSession.set(id,rec);const sla=rec.checks?rec.up/rec.checks*100:100;const se=card.querySelector('.sla-value');if(se)se.textContent=sla.toFixed(3)+'%';const z=Math.max(anomalyScore(h.rx,item.rx_mbps),anomalyScore(h.tx,item.tx_mbps)),ae=card.querySelector('.anomaly-intel'),av=card.querySelector('.anomaly-value');if(ae){ae.classList.remove('warning','critical');if(z>=4){ae.classList.add('critical');av.textContent='Critical '+z.toFixed(1)+'σ';card.classList.add('anomaly-flash');showNocAlert(item,'warning','Traffic anomaly '+z.toFixed(1)+' standard deviations')}else if(z>=2.7){ae.classList.add('warning');av.textContent='Elevated '+z.toFixed(1)+'σ'}else av.textContent='Normal'}const forecast=Math.max(linearForecast(h.rx)||0,linearForecast(h.tx)||0),speed=Number(item.speed_mbps||0),fe=card.querySelector('.forecast-value');if(fe)fe.textContent=!speed?'No speed':forecast<=0?'Stable':Math.min(999,forecast/speed*100).toFixed(1)+'% / next';const critical=status!=='up'||Number(item.util_pct||0)>=85;card.classList.toggle('pinned-critical',pinCriticalEnabled&&critical);if(status!=='up')showNocAlert(item,'down','Interface status '+status.toUpperCase());else if(Number(item.util_pct||0)>=85)showNocAlert(item,'warning','High utilization '+Number(item.util_pct).toFixed(1)+'%');trackPortIncidents(item,z);const health=calculateHealthScore(item,h,sla,z);updateHealthUI(card,health);updateTimelineCount(id)}
function resortCritical(){if(!pinCriticalEnabled)return;[...cardsEl.querySelectorAll('.card')].sort((a,b)=>b.classList.contains('pinned-critical')-a.classList.contains('pinned-critical')).forEach(c=>cardsEl.appendChild(c))}
function updateStats(card,item,h){card.querySelector('.rxcur').textContent=fmt(item.rx_mbps); card.querySelector('.txcur').textContent=fmt(item.tx_mbps); card.querySelector('.rxavg').textContent=fmt(avg(h.rx)); card.querySelector('.txavg').textContent=fmt(avg(h.tx)); card.querySelector('.rxmax').textContent=fmt(max(h.rx)); card.querySelector('.txmax').textContent=fmt(max(h.tx)); card.querySelector('.rxdisc').textContent=Number(item.rxdisc||0).toFixed(0); card.querySelector('.txerr').textContent=Number(item.txerr||0).toFixed(0); card.querySelector('.util').textContent=Number(item.util_pct||0).toFixed(1)+'%'; card.querySelector('.badge').textContent=String(item.status||'up').toUpperCase(); const trafficNow=Math.max(Number(item.rx_mbps||0),Number(item.tx_mbps||0)); card.classList.toggle('zero-traffic',trafficNow<0.001); card.classList.toggle('has-traffic',trafficNow>=0.001); card.classList.toggle('status-down',String(item.status||'up').toLowerCase()!=='up'); const miniRx=card.querySelector('.mini-rx'),miniTx=card.querySelector('.mini-tx'),miniUtil=card.querySelector('.mini-util'); if(miniRx)miniRx.textContent=fmt(item.rx_mbps); if(miniTx)miniTx.textContent=fmt(item.tx_mbps); if(miniUtil)miniUtil.textContent=Number(item.util_pct||0).toFixed(1)+'%'; const ur=card.querySelector('.unitrx'), ut=card.querySelector('.unittx'); if(ur)ur.textContent='RX '+fmt(item.rx_mbps); if(ut)ut.textContent='TX '+fmt(item.tx_mbps); const p95r=card.querySelector('.p95rx'),p95t=card.querySelector('.p95tx'); if(p95r)p95r.textContent=fmt(p95(h.rx)); if(p95t)p95t.textContent=fmt(p95(h.tx)); card.classList.remove('th-ok','th-warn','th-crit'); const u=Number(item.util_pct||0); card.classList.add(u>=85?'th-crit':u>=65?'th-warn':'th-ok'); updateIntelligence(card,item,h); resortCritical()} 
async function updateLive(item){const card=makeCard(item); let h=hist.get(item.port_id)||{t:[],rx:[],tx:[]}; h.t.push(nowLabel()); h.rx.push(Number(item.rx_mbps||0)); h.tx.push(Number(item.tx_mbps||0)); while(h.t.length>MAX_POINTS){h.t.shift();h.rx.shift();h.tx.shift()} hist.set(item.port_id,h); card.querySelector('.warnmsg').textContent=''; updateStats(card,item,h); const cv=card.querySelector('canvas'); draw(cv,h); attachTooltip(card,cv); enableDragResize(card,item.port_id); enableDragMove(card,item.port_id)}
async function updateHistory(item){const card=makeCard(item); let url=`?api=history&port_id=${item.port_id}&range=${currentRange}`; if(currentRange==='custom') url+=`&from=${encodeURIComponent(customFrom)}&to=${encodeURIComponent(customTo)}`; const res=await getJson(url); const h={t:[],rx:[],tx:[]}; const span=(Number(res.to||0)-Number(res.from||0))||0; (res.data||[]).forEach(p=>{h.t.push(fmtAxis(p.t,span)); h.rx.push(Number(p.rx||0)); h.tx.push(Number(p.tx||0))}); hist.set(item.port_id,h); card.querySelector('.warnmsg').textContent=res.warning?res.warning:''; if(res.warning)console.warn('History debug',res); updateStats(card,item,h); const cv=card.querySelector('canvas'); draw(cv,h); attachTooltip(card,cv); enableDragResize(card,item.port_id); enableDragMove(card,item.port_id)}


async function loadProfiles(){
  try{
    const r=await getJson('?api=profiles_load');
    const profiles=(r&&r.profiles&&typeof r.profiles==='object')?r.profiles:null;
    if(profiles){
      const previous=profileSelect.value;
      profileSelect.innerHTML=IS_ADMIN?'<option value="__new__">+ New Dashboard / Kosong</option>':'<option value="">Pilih dashboard untuk dilihat...</option>';
      Object.entries(profiles).forEach(([name,ids])=>{const clean=(ids||[]).map(Number).filter(x=>x>0);const o=document.createElement('option');o.value=name;o.textContent=name+' ('+clean.length+' port)';o.dataset.ids=JSON.stringify(clean);profileSelect.appendChild(o);});
      const wanted=currentProfile||previous||r.last_profile||'';
      if(wanted&&profiles[wanted]){currentProfile=wanted;profileSelect.value=wanted;const pn=document.getElementById('profileName');if(pn)pn.value=wanted;selectedIds=(profiles[wanted]||[]).map(Number).filter(x=>x>0);localStorage.setItem('bw_selected_ports',JSON.stringify(selectedIds));localStorage.setItem('bw_profile',wanted);}
    }
  }catch(e){
    console.warn('load profile API gagal, menggunakan option dari dashboard_profiles.json yang dirender server',e);
    const selected=profileSelect.options[profileSelect.selectedIndex];
    if(selected&&selected.value&&selected.dataset.ids){currentProfile=selected.value;selectedIds=JSON.parse(selected.dataset.ids||'[]').map(Number).filter(x=>x>0);localStorage.setItem('bw_profile',currentProfile);localStorage.setItem('bw_selected_ports',JSON.stringify(selectedIds));}
  }
}
async function saveProfile(name){if(!IS_ADMIN){alert('Role Viewer tidak boleh menyimpan dashboard.');return;}
  name=(name||profileName.value||currentProfile||'Default').trim(); if(!name){alert('Isi nama dashboard dulu bre'); return;}
  saveStatus.textContent='saving profile...';
  try{const r=await fetch('?api=profiles_save',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF_TOKEN},body:JSON.stringify({name,ports:selectedIds})}); const j=await r.json(); if(!r.ok||j.ok===false)throw new Error(j.error||'save profile failed'); currentProfile=j.name; profileName.value=j.name; localStorage.setItem('bw_profile',j.name); localStorage.setItem('bw_selected_ports',JSON.stringify(selectedIds)); saveStatus.textContent='saved dashboard: '+j.name; await loadProfiles(); renderChips();}
  catch(e){saveStatus.textContent='save profile gagal: '+e.message; console.warn(e)}
}
function newBlankDashboard(){currentProfile=''; selectedIds=[]; profileName.value=''; profileSelect.value='__new__'; localStorage.removeItem('bw_profile'); localStorage.removeItem('bw_selected_ports'); hist.clear(); renderChips(); tick(); saveStatus.textContent='new blank dashboard';}
profileSelect.onchange=async()=>{
  const o=profileSelect.options[profileSelect.selectedIndex];
  if(!o)return;
  if(o.value==='__new__'){
    if(IS_ADMIN)newBlankDashboard();
    return;
  }
  if(!o.value)return;
  try{
    const ids=JSON.parse(o.dataset.ids||'[]').map(Number).filter(x=>x>0);
    currentProfile=o.value;
    selectedIds=[...new Set(ids)];
    const pn=document.getElementById('profileName');if(pn)pn.value=currentProfile;
    localStorage.setItem('bw_profile',currentProfile);
    localStorage.setItem('bw_selected_ports',JSON.stringify(selectedIds));
    hist.clear();meta.clear();
    cardsEl.innerHTML='<div class="empty">Loading dashboard '+esc(currentProfile)+'...</div>';
    renderChips();
    if(typeof saveStatus!=='undefined')saveStatus.textContent='viewing dashboard: '+currentProfile+' ('+selectedIds.length+' port)';const vps=document.getElementById('viewerProfileStatus');if(vps)vps.textContent='Aktif: '+currentProfile+' ('+selectedIds.length+' port)';
    refreshRemaining=Math.max(1,Math.round(REFRESH_MS/1000));
    await tick();
  }catch(e){
    console.error('switch dashboard gagal',e);
    if(typeof saveStatus!=='undefined')saveStatus.textContent='gagal membuka dashboard: '+e.message;
    alert('Gagal membuka dashboard '+o.value+': '+e.message);
  }
};
if(document.getElementById('saveAsBtn'))document.getElementById('saveAsBtn').onclick=()=>saveProfile((document.getElementById('profileName')||{}).value||'');
if(document.getElementById('newDashboardBtn'))document.getElementById('newDashboardBtn').onclick=()=>newBlankDashboard();
deleteProfileBtn.onclick=async()=>{const name=profileSelect.value||profileName.value; if(!name){alert('Pilih dashboard yang mau dihapus'); return;} if(!confirm('Hapus dashboard '+name+'?'))return; try{const r=await fetch('?api=profiles_delete',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF_TOKEN},body:JSON.stringify({name})}); const j=await r.json(); if(!r.ok||j.ok===false)throw new Error(j.error||'delete failed'); if(currentProfile===name){currentProfile=''; localStorage.removeItem('bw_profile');} profileName.value=''; saveStatus.textContent='deleted dashboard: '+name; await loadProfiles();}catch(e){saveStatus.textContent='delete gagal: '+e.message;}};
async function loadGroups(){try{const g=await getJson('?api=groups'); groupSelect.innerHTML='<option value="">Group...</option>'; Object.entries(g.groups||{}).forEach(([name,ids])=>{const o=document.createElement('option'); o.value=name; o.textContent=name+' ('+(ids||[]).length+')'; o.dataset.ids=JSON.stringify(ids||[]); groupSelect.appendChild(o);});}catch(e){console.warn(e)}}
groupSelect.onchange=()=>{const o=groupSelect.options[groupSelect.selectedIndex]; if(!o||!o.dataset.ids)return; const ids=JSON.parse(o.dataset.ids||'[]').map(Number).filter(x=>x>0); if(ids.length){selectedIds=ids; saveIds(); saveCurrentProfileSilent(); tick();}};
function renderTopList(el,arr,field,suffix){el.innerHTML=''; (arr||[]).slice(0,10).forEach(x=>{const d=document.createElement('div'); d.className='topitem'; d.innerHTML='<span title="'+esc(x.title)+'">'+esc(x.title)+'</span><b>'+ (field==='util_pct'?Number(x[field]||0).toFixed(1)+'%':fmt(x[field])) +'</b>'; el.appendChild(d);});}
async function loadTopTraffic(){try{const t=await getJson('?api=top_traffic'); renderTopList(topRx,t.rx,'rx_mbps'); renderTopList(topTx,t.tx,'tx_mbps'); renderTopList(topUtil,t.util,'util_pct');}catch(e){console.warn('top traffic gagal',e)}}
function applyTheme(){const t=localStorage.getItem('bw_theme')||'light'; document.body.classList.remove('dark','theme-noc','theme-ocean'); if(t==='dark')document.body.classList.add('dark'); if(t==='noc')document.body.classList.add('theme-noc'); if(t==='ocean')document.body.classList.add('theme-ocean'); document.body.classList.toggle('tv',localStorage.getItem('bw_tv')==='1'); if(typeof themeSelect!=='undefined')themeSelect.value=t;}
themeSelect.onchange=()=>{localStorage.setItem('bw_theme',themeSelect.value); applyTheme();};
tvBtn.onclick=()=>{localStorage.setItem('bw_tv',localStorage.getItem('bw_tv')==='1'?'0':'1'); applyTheme();}; exitTvBtn.onclick=()=>{localStorage.setItem('bw_tv','0'); applyTheme();}; document.addEventListener('keydown',e=>{if(e.key==='Escape'){localStorage.setItem('bw_tv','0'); applyTheme();}});

function wordSafeHtml(v){
  return String(v ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#039;');
}
function currentRangeLabel(){
  if(currentRange === 'custom') return 'Custom: ' + (customFrom || '-') + ' s/d ' + (customTo || '-');
  const map = {live:'Live',hour:'Last 1 hour',day:'Last 24 hours',week:'Last 7 days',month:'Last 30 days'};
  return map[currentRange] || currentRange || '-';
}
function cardLegendRowsForWord(card){
  const rows = [...card.querySelectorAll('.legend-table tr')].map(tr => {
    const cells = [...tr.querySelectorAll('td')].map(td => wordSafeHtml(td.innerText.trim()));
    if(!cells.length) return '';
    return '<tr>' + cells.map(c => '<td>' + c + '</td>').join('') + '</tr>';
  }).join('');
  return rows ? '<table class="legend">' + rows + '</table>' : '';
}
async function exportDashboardDoc(){
  try{
    const cards = [...document.querySelectorAll('.grid .card')];
    if(!cards.length){ alert('Belum ada grafik/card yang bisa diexport bre.'); return; }
    saveStatus.textContent = 'preparing .doc...';

    const summaryHtml = [...document.querySelectorAll('.summary .kpi')].map(k => {
      const label = k.querySelector('span') ? k.querySelector('span').innerText.trim() : '';
      const value = k.querySelector('b') ? k.querySelector('b').innerText.trim() : '';
      return '<td><b>' + wordSafeHtml(value) + '</b><br><span>' + wordSafeHtml(label) + '</span></td>';
    }).join('');

    // Word sering tidak menampilkan gambar kalau pakai data:image/png;base64 langsung.
    // Karena itu export dibuat ke format MHTML .doc dan image direferensikan pakai cid:...
    const imageParts = [];
    let cardsHtml = '';
    let imgIdx = 0;

    for(const card of cards){
      const title = card.querySelector('.title') ? card.querySelector('.title').innerText.trim() : card.id;
      const canvas = card.querySelector('canvas.chart');
      let imgHtml = '<p class="muted">Grafik tidak tersedia.</p>';

      if(canvas){
        const portId = Number((card.id || '').replace('port-',''));
        const h = hist.get(portId);
        if(h) draw(canvas, h);

        const dataUrl = canvas.toDataURL('image/png');
        const base64 = (dataUrl.split(',')[1] || '').trim();
        if(base64){
          const cid = 'chart' + imgIdx + '.png';
          imageParts.push({cid, base64});
          imgHtml = '<p><img src="cid:' + cid + '" width="650" style="width:650px;max-width:100%;height:auto;border:1px solid #d6e1e8;" /></p>';
          imgIdx++;
        }
      }

      const status = card.querySelector('.status') ? card.querySelector('.status').innerText.trim() : '';
      const warning = card.querySelector('.warnmsg') ? card.querySelector('.warnmsg').innerText.trim() : '';
      cardsHtml += '<div class="card-block">'
        + '<h2>' + wordSafeHtml(title) + '</h2>'
        + (status ? '<p class="muted">' + wordSafeHtml(status) + '</p>' : '')
        + (warning ? '<p class="warning">' + wordSafeHtml(warning) + '</p>' : '')
        + imgHtml
        + cardLegendRowsForWord(card)
        + '</div>';
    }

    const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>LibreNMS Bandwidth Dashboard Export</title>
<style>
@page WordSection1 { size: A4; margin: 18mm 14mm 18mm 14mm; }
body { font-family: Arial, Helvetica, sans-serif; color:#1d2b36; font-size:10pt; }
h1 { font-size:18pt; color:#263845; border-bottom:3px solid #263845; padding-bottom:6px; }
h2 { font-size:13pt; color:#18384c; margin:16px 0 6px; }
.meta { color:#526879; margin-bottom:10px; }
.summary { border-collapse:collapse; width:100%; margin:10px 0 14px; }
.summary td { border:1px solid #ccd6dd; padding:8px; background:#f7fafc; }
.summary b { font-size:15pt; color:#18384c; }
.legend { border-collapse:collapse; width:100%; margin-top:6px; font-size:8.5pt; }
.legend td { border-bottom:1px solid #edf2f5; padding:3px 4px; }
.card-block { page-break-inside:avoid; margin-bottom:18px; }
.muted { color:#60727f; }.warning { color:#b36b00; }
</style></head><body>
<h1>LibreNMS Bandwidth Dashboard</h1>
<p class="meta"><b>Generated:</b> ${wordSafeHtml(new Date().toLocaleString('id-ID'))}<br>
<b>Range:</b> ${wordSafeHtml(currentRangeLabel())}<br>
<b>Profile:</b> ${wordSafeHtml(currentProfile || profileName.value || 'Default / Browser')}<br>
<b>Charts exported:</b> ${imageParts.length}</p>
<table class="summary"><tr>${summaryHtml}</tr></table>
${cardsHtml}
</body></html>`;

    const boundary = '----=_LibreNMS_Doc_' + Date.now();
    let mhtml = 'MIME-Version: 1.0\r\n'
      + 'Content-Type: multipart/related; boundary="' + boundary + '"; type="text/html"\r\n\r\n'
      + '--' + boundary + '\r\n'
      + 'Content-Type: text/html; charset="utf-8"\r\n'
      + 'Content-Transfer-Encoding: 8bit\r\n'
      + 'Content-Location: file:///dashboard.html\r\n\r\n'
      + html + '\r\n';

    imageParts.forEach(img => {
      mhtml += '--' + boundary + '\r\n'
        + 'Content-Type: image/png\r\n'
        + 'Content-Transfer-Encoding: base64\r\n'
        + 'Content-ID: <' + img.cid + '>\r\n'
        + 'Content-Location: ' + img.cid + '\r\n\r\n'
        + img.base64.replace(/(.{76})/g, '$1\r\n') + '\r\n';
    });
    mhtml += '--' + boundary + '--';

    const blob = new Blob(['\ufeff', mhtml], {type:'application/msword;charset=utf-8'});
    const a = document.createElement('a');
    const ts = new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');
    a.href = URL.createObjectURL(blob);
    a.download = 'librenms_bandwidth_dashboard_' + ts + '.doc';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    saveStatus.textContent = 'export .doc done (' + imageParts.length + ' gambar)';
  }catch(e){
    console.error(e);
    saveStatus.textContent = 'export .doc gagal';
    alert('Export .doc gagal: ' + e.message);
  }
}
if(typeof exportDocBtn !== 'undefined') exportDocBtn.onclick = exportDashboardDoc;




function parseCsvLine(line){
  const out = [];
  let cur = '', inQuotes = false;
  for(let i=0;i<line.length;i++){
    const ch = line[i];
    if(ch === '"'){
      if(inQuotes && line[i+1] === '"') { cur += '"'; i++; }
      else inQuotes = !inQuotes;
    } else if(ch === ',' && !inQuotes){
      out.push(cur); cur = '';
    } else cur += ch;
  }
  out.push(cur);
  return out;
}
function parseExportCsv(text){
  text = String(text || '').replace(/^\ufeff/, '').trim();
  const lines = text.split(/\r?\n/).filter(Boolean);
  if(lines.length < 2) return [];
  const header = parseCsvLine(lines[0]).map(h => h.trim());
  return lines.slice(1).map(line => {
    const vals = parseCsvLine(line);
    const row = {};
    header.forEach((h,i) => row[h] = vals[i] ?? '');
    return row;
  });
}
function csvNum(v){
  if(v === null || v === undefined || v === '') return 0;
  const n = Number(String(v).replace(',', '.'));
  return Number.isFinite(n) ? n : 0;
}
function labelForSummaryRow(row){
  const alias = String(row.alias || '').trim();
  const iface = String(row.interface || '').trim();
  const dev = String(row.device || '').trim();
  let label = (alias ? alias : iface ? iface : 'port_' + (row.port_id || ''));
  if(dev) label = dev + ' - ' + label;
  return label;
}
function formatMbpsAxis(v){
  v = Number(v || 0);
  if(v >= 1000) return (v / 1000).toFixed(1) + ' Gbps';
  if(v >= 1) return v.toFixed(1) + ' Mbps';
  return (v * 1000).toFixed(0) + ' Kbps';
}
function formatMbpsCell(v){
  v = Number(v || 0);
  return v.toFixed(3);
}
function drawAllSummaryBarChart(rows, metricPrefix, title){
  const prepared = rows.map(row => ({
    label: labelForSummaryRow(row),
    rx: csvNum(row[metricPrefix + '_rx_mbps']),
    tx: csvNum(row[metricPrefix + '_tx_mbps'])
  }));
  const rowH = 58;
  const width = 1500;
  const height = Math.max(520, 140 + prepared.length * rowH + 70);
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0,0,width,height);

  ctx.fillStyle = '#263845';
  ctx.font = 'bold 34px Arial';
  ctx.fillText(title, 36, 48);
  ctx.font = '16px Arial';
  ctx.fillStyle = '#60727f';
  ctx.fillText('Source: Export CSV summary data | Unit: Mbps | Generated ' + new Date().toLocaleString('id-ID'), 36, 78);

  const left = 430, right = 70, top = 125;
  const plotW = width - left - right;
  const maxVal = Math.max(1, ...prepared.map(x => Math.max(x.rx, x.tx))) * 1.12;

  // grid and axis labels
  ctx.strokeStyle = '#dbe6ed';
  ctx.lineWidth = 1;
  ctx.font = '13px Arial';
  ctx.fillStyle = '#60727f';
  for(let i=0;i<=5;i++){
    const x = left + plotW * i / 5;
    ctx.beginPath(); ctx.moveTo(x, top - 30); ctx.lineTo(x, top + prepared.length * rowH); ctx.stroke();
    ctx.fillText(formatMbpsAxis(maxVal * i / 5), x - 25, top + prepared.length * rowH + 24);
  }

  prepared.forEach((item, idx) => {
    const y = top + idx * rowH;
    const rxW = plotW * item.rx / maxVal;
    const txW = plotW * item.tx / maxVal;
    // alternate row background
    ctx.fillStyle = idx % 2 === 0 ? '#f7fafc' : '#ffffff';
    ctx.fillRect(20, y - 10, width - 40, rowH - 6);

    ctx.fillStyle = '#18384c';
    ctx.font = 'bold 15px Arial';
    let label = (idx + 1) + '. ' + item.label;
    if(label.length > 48) label = label.slice(0,48) + '...';
    ctx.fillText(label, 36, y + 12);

    ctx.fillStyle = '#edf4f8';
    ctx.fillRect(left, y, plotW, 17);
    ctx.fillRect(left, y + 23, plotW, 17);

    ctx.fillStyle = '#00D6A3';
    ctx.fillRect(left, y, Math.max(2, rxW), 17);
    ctx.fillStyle = '#6C63FF';
    ctx.fillRect(left, y + 23, Math.max(2, txW), 17);

    ctx.font = 'bold 13px Arial';
    ctx.fillStyle = '#0b5d50';
    ctx.fillText('RX ' + formatMbpsAxis(item.rx), left + Math.min(rxW + 8, plotW - 95), y + 13);
    ctx.fillStyle = '#145c91';
    ctx.fillText('TX ' + formatMbpsAxis(item.tx), left + Math.min(txW + 8, plotW - 95), y + 36);
  });

  // legend
  const ly = height - 32;
  ctx.fillStyle = '#00D6A3'; ctx.fillRect(36, ly - 9, 22, 11);
  ctx.fillStyle = '#1d2b36'; ctx.font = '15px Arial'; ctx.fillText('RX', 66, ly);
  ctx.fillStyle = '#6C63FF'; ctx.fillRect(118, ly - 9, 22, 11);
  ctx.fillStyle = '#1d2b36'; ctx.fillText('TX', 148, ly);

  return canvas.toDataURL('image/png');
}
async function exportCsvWithChart(){
  try{
    const ids=selectedIds.join(',');
    if(!ids){ alert('Belum ada port yang dipilih'); return; }
    saveStatus.textContent = 'ambil CSV summary...';
    let url='?api=export_report&ids='+ids+'&range='+currentRange;
    if(currentRange==='custom') url+='&from='+encodeURIComponent(customFrom)+'&to='+encodeURIComponent(customTo);
    url+='&ts='+Date.now();
    const res = await fetch(url, {cache:'no-store'});
    const csvText = await res.text();
    if(!res.ok) throw new Error('HTTP '+res.status+' | '+csvText.slice(0,200));
    const rows = parseExportCsv(csvText);
    if(!rows.length) throw new Error('CSV summary kosong / tidak valid');

    saveStatus.textContent = 'generate bar chart dari CSV...';
    const imageParts = [];
    function addChart(dataUrl, name){
      const base64 = (dataUrl.split(',')[1] || '').trim();
      if(!base64) return '';
      const cid = name + '.png';
      imageParts.push({cid, base64});
      return '<img src="cid:' + cid + '" width="920" style="width:920px;max-width:100%;height:auto;border:1px solid #d6e1e8;" />';
    }

    const avgImg = addChart(drawAllSummaryBarChart(rows, 'avg', 'Average Bandwidth - All Summary Data'), 'avg_bandwidth_all');
    const maxImg = addChart(drawAllSummaryBarChart(rows, 'max', 'Maximum Bandwidth - All Summary Data'), 'max_bandwidth_all');
    const p95Img = addChart(drawAllSummaryBarChart(rows, 'p95', '95th Percentile Bandwidth - All Summary Data'), 'p95_bandwidth_all');

    const summaryHtml = [...document.querySelectorAll('.summary .kpi')].map(k => {
      const label = k.querySelector('span') ? k.querySelector('span').innerText.trim() : '';
      const value = k.querySelector('b') ? k.querySelector('b').innerText.trim() : '';
      return '<td><b>' + wordSafeHtml(value) + '</b><br><span>' + wordSafeHtml(label) + '</span></td>';
    }).join('');

    const dataRows = rows.map(row => '<tr>'
      + '<td>' + wordSafeHtml(row.port_id) + '</td>'
      + '<td>' + wordSafeHtml(row.device) + '</td>'
      + '<td>' + wordSafeHtml(row.interface) + '</td>'
      + '<td>' + wordSafeHtml(row.alias) + '</td>'
      + '<td>' + formatMbpsCell(csvNum(row.avg_rx_mbps)) + '</td>'
      + '<td>' + formatMbpsCell(csvNum(row.avg_tx_mbps)) + '</td>'
      + '<td>' + formatMbpsCell(csvNum(row.max_rx_mbps)) + '</td>'
      + '<td>' + formatMbpsCell(csvNum(row.max_tx_mbps)) + '</td>'
      + '<td>' + formatMbpsCell(csvNum(row.p95_rx_mbps)) + '</td>'
      + '<td>' + formatMbpsCell(csvNum(row.p95_tx_mbps)) + '</td>'
      + '</tr>').join('');

    const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>LibreNMS Bandwidth Bar Chart Export</title>
<style>
body { font-family: Arial, Helvetica, sans-serif; color:#1d2b36; font-size:10pt; }
h1 { font-size:18pt; color:#263845; border-bottom:3px solid #263845; padding-bottom:6px; }
h2 { font-size:13pt; color:#18384c; margin:18px 0 8px; }
.meta { color:#526879; margin-bottom:10px; }
.summary { border-collapse:collapse; width:100%; margin:10px 0 14px; }
.summary td { border:1px solid #ccd6dd; padding:8px; background:#f7fafc; }
.summary b { font-size:15pt; color:#18384c; }
.data-table { border-collapse:collapse; width:100%; margin-top:8px; font-size:9pt; }
.data-table td,.data-table th { border:1px solid #d9e2e8; padding:4px 5px; }
.data-table th { background:#edf4f8; color:#18384c; }
.chart-block { page-break-inside:avoid; margin-bottom:20px; }
.small { color:#60727f; font-size:9pt; }
</style></head><body>
<h1>LibreNMS Bandwidth Summary - Bar Chart</h1>
<p class="meta"><b>Generated:</b> ${wordSafeHtml(new Date().toLocaleString('id-ID'))}<br>
<b>Range:</b> ${wordSafeHtml(currentRangeLabel())}<br>
<b>Profile:</b> ${wordSafeHtml(currentProfile || profileName.value || 'Default / Browser')}<br>
<b>Source:</b> Data dari Export CSV summary, unit Mbps</p>
<table class="summary"><tr>${summaryHtml}</tr></table>
<div class="chart-block"><h2>Average RX/TX Mbps</h2><p class="small">Bar chart dibuat dari kolom avg_rx_mbps dan avg_tx_mbps.</p>${avgImg}</div>
<div class="chart-block"><h2>Maximum RX/TX Mbps</h2><p class="small">Bar chart dibuat dari kolom max_rx_mbps dan max_tx_mbps.</p>${maxImg}</div>
<div class="chart-block"><h2>95th RX/TX Mbps</h2><p class="small">Bar chart dibuat dari kolom p95_rx_mbps dan p95_tx_mbps.</p>${p95Img}</div>
<h2>CSV Summary Data</h2>
<table class="data-table"><tr><th>port_id</th><th>device</th><th>interface</th><th>alias</th><th>avg_rx_mbps</th><th>avg_tx_mbps</th><th>max_rx_mbps</th><th>max_tx_mbps</th><th>p95_rx_mbps</th><th>p95_tx_mbps</th></tr>${dataRows}</table>
</body></html>`;

    const boundary = '----=_LibreNMS_Bar_XLS_' + Date.now();
    let mhtml = 'MIME-Version: 1.0\r\n'
      + 'Content-Type: multipart/related; boundary="' + boundary + '"; type="text/html"\r\n\r\n'
      + '--' + boundary + '\r\n'
      + 'Content-Type: text/html; charset="utf-8"\r\n'
      + 'Content-Transfer-Encoding: 8bit\r\n'
      + 'Content-Location: file:///bandwidth_bar_chart.xls\r\n\r\n'
      + html + '\r\n';
    imageParts.forEach(img => {
      mhtml += '--' + boundary + '\r\n'
        + 'Content-Type: image/png\r\n'
        + 'Content-Transfer-Encoding: base64\r\n'
        + 'Content-ID: <' + img.cid + '>\r\n'
        + 'Content-Location: ' + img.cid + '\r\n\r\n'
        + img.base64.replace(/(.{76})/g, '$1\r\n') + '\r\n';
    });
    mhtml += '--' + boundary + '--';

    const blob = new Blob(['\ufeff', mhtml], {type:'application/vnd.ms-excel;charset=utf-8'});
    const a = document.createElement('a');
    const ts = new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');
    a.href = URL.createObjectURL(blob);
    a.download = 'librenms_bandwidth_bar_chart_' + ts + '.xls';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    saveStatus.textContent = 'export bar chart done (' + rows.length + ' row)';
  }catch(e){
    console.error(e);
    saveStatus.textContent = 'export bar chart gagal';
    alert('Export bar chart gagal: ' + e.message);
  }
}
if(typeof exportChartBtn !== 'undefined') exportChartBtn.onclick = exportCsvWithChart;
exportBtn.onclick=()=>{const ids=selectedIds.join(','); if(!ids){alert('Belum ada port yang dipilih'); return;} let url='?api=export_report&ids='+ids+'&range='+currentRange; if(currentRange==='custom')url+='&from='+encodeURIComponent(customFrom)+'&to='+encodeURIComponent(customTo); window.open(url,'_blank');};
async function loadSummary(){const s=await getJson('?api=summary'); devTotal.textContent=s.devices_total??0;devUp.textContent=s.devices_up??0;devDown.textContent=s.devices_down??0;alerts.textContent=s.alerts_active??0;rxTotal.textContent=Number(s.rx_mbps??0).toFixed(2);txTotal.textContent=Number(s.tx_mbps??0).toFixed(2)} async function loadPorts(){if(layoutDragging)return; const ids=selectedIds.join(','); const res=await getJson('?api=ports'+(ids?'&ids='+ids:'')); let data=res.data||[]; data=applySavedOrder(data); if(data.length===0){cardsEl.innerHTML='<div class="empty">Belum ada port. Cari port di atas, pilih, lalu klik Tambah Port.</div>'; return} cardsEl.querySelectorAll('.empty').forEach(e=>e.remove()); const seen=new Set(); for(const item of data){seen.add('port-'+item.port_id); if(currentRange==='live')await updateLive(item); else await updateHistory(item)} document.querySelectorAll('.card').forEach(c=>{if(!seen.has(c.id)){c.remove();hist.delete(Number(c.id.replace('port-','')))}}); renderChips(); lastUpdate.textContent='Last update: '+(res.ts||new Date().toLocaleString('id-ID'))}
let livePaused=false,refreshRemaining=Math.max(1,Math.round(REFRESH_MS/1000));
function updateCommandDeck(ok=true){
  const health=document.getElementById('systemHealthText'),dash=document.getElementById('activeDashboardLabel'),widgets=document.getElementById('widgetCount'),mode=document.getElementById('dataModeLabel'),countdown=document.getElementById('refreshCountdown');
  if(health)health.textContent=ok?'LibreNMS Connected':'Connection Warning';
  if(dash)dash.textContent=currentProfile||'Unsaved Workspace';
  if(widgets)widgets.textContent=selectedIds.length+' Ports';
  if(mode)mode.textContent=livePaused?'Live Paused':(currentRange==='live'?'Live Stream':String(currentRange).toUpperCase()+' History');
  if(countdown)countdown.textContent=livePaused?'PAUSED':refreshRemaining+'s';
}
const densityBtn=document.getElementById('densityBtn'),autoFitBtn=document.getElementById('autoFitBtn'),focusBtn=document.getElementById('focusBtn'),pauseLiveBtn=document.getElementById('pauseLiveBtn'),manualRefreshBtn=document.getElementById('manualRefreshBtn');const performanceBtn=document.getElementById('performanceBtn'),performancePanel=document.getElementById('performancePanel'),closePerformancePanel=document.getElementById('closePerformancePanel'),resetPerformanceMetrics=document.getElementById('resetPerformanceMetrics'),closeDetailDrawerBtn=document.getElementById('closeDetailDrawer'),drawerBackdrop=document.getElementById('drawerBackdrop');const visualFxBtn=document.getElementById('visualFxBtn');
function applyVisualFx(){const on=localStorage.getItem('bw_visual_fx')!=='0';document.body.classList.toggle('visual-fx',on);if(visualFxBtn){visualFxBtn.classList.toggle('active',on);visualFxBtn.textContent=on?'Visual FX On':'Visual FX Off'}}if(visualFxBtn)visualFxBtn.onclick=()=>{localStorage.setItem('bw_visual_fx',document.body.classList.contains('visual-fx')?'0':'1');applyVisualFx()};applyVisualFx();
let fxFrames=0,fxStarted=performance.now();function visualFpsGuard(t){fxFrames++;if(t-fxStarted>=5000){const fps=fxFrames/((t-fxStarted)/1000);document.body.classList.toggle('fx-low',fps<24);fxFrames=0;fxStarted=t}requestAnimationFrame(visualFpsGuard)}requestAnimationFrame(visualFpsGuard);
if(performanceBtn)performanceBtn.onclick=()=>{performancePanel.classList.toggle('open');performancePanel.setAttribute('aria-hidden',performancePanel.classList.contains('open')?'false':'true');updatePerformanceUI()};if(closePerformancePanel)closePerformancePanel.onclick=()=>performancePanel.classList.remove('open');if(resetPerformanceMetrics)resetPerformanceMetrics.onclick=()=>{perfMetrics.requests={};perfMetrics.errors=0;perfMetrics.tick=0;perfMetrics.render=0;updatePerformanceUI()};if(closeDetailDrawerBtn)closeDetailDrawerBtn.onclick=closeDetailDrawer;if(drawerBackdrop)drawerBackdrop.onclick=closeDetailDrawer;document.addEventListener('keydown',e=>{if(e.key==='Escape'&&document.getElementById('detailDrawer').classList.contains('open'))closeDetailDrawer()});
const rotateBtn=document.getElementById('rotateBtn'),pinCriticalBtn=document.getElementById('pinCriticalBtn'),exitWidgetFullscreen=document.getElementById('exitWidgetFullscreen');
function stopProfileRotation(){if(rotateTimer){clearInterval(rotateTimer);rotateTimer=null}if(rotateBtn){rotateBtn.classList.remove('active');rotateBtn.textContent='Rotate Off'}localStorage.setItem('bw_rotate','0')}
function rotateProfileNow(){const opts=[...profileSelect.options].filter(o=>o.value&&o.value!=='__new__');if(opts.length<2)return;let i=opts.findIndex(o=>o.value===profileSelect.value);profileSelect.value=opts[(i+1)%opts.length].value;profileSelect.dispatchEvent(new Event('change'))}
function startProfileRotation(){stopProfileRotation();rotateTimer=setInterval(rotateProfileNow,60000);if(rotateBtn){rotateBtn.classList.add('active');rotateBtn.textContent='Rotate 60s'}localStorage.setItem('bw_rotate','1')}
if(rotateBtn)rotateBtn.onclick=()=>rotateTimer?stopProfileRotation():startProfileRotation();if(localStorage.getItem('bw_rotate')==='1')setTimeout(startProfileRotation,2500);
if(pinCriticalBtn){pinCriticalBtn.classList.toggle('active',pinCriticalEnabled);pinCriticalBtn.textContent=pinCriticalEnabled?'Pinned On':'Pin Critical';pinCriticalBtn.onclick=()=>{pinCriticalEnabled=!pinCriticalEnabled;localStorage.setItem('bw_pin_critical',pinCriticalEnabled?'1':'0');pinCriticalBtn.classList.toggle('active',pinCriticalEnabled);pinCriticalBtn.textContent=pinCriticalEnabled?'Pinned On':'Pin Critical';document.querySelectorAll('.card').forEach(c=>{if(!pinCriticalEnabled)c.classList.remove('pinned-critical')});tick()}}
const incidentModal=document.getElementById('incidentModal'),closeIncidentModal=document.getElementById('closeIncidentModal'),clearIncidentTimeline=document.getElementById('clearIncidentTimeline'),exportIncidentTimeline=document.getElementById('exportIncidentTimeline');if(closeIncidentModal)closeIncidentModal.onclick=closeIncident;if(incidentModal)incidentModal.addEventListener('click',e=>{if(e.target===incidentModal)closeIncident()});if(clearIncidentTimeline)clearIncidentTimeline.onclick=()=>{if(!IS_ADMIN){alert('Role Viewer tidak boleh menghapus timeline.');return;}if(!activeIncidentPortId)return;if(!confirm('Clear incident timeline port ini?'))return;saveIncidentTimeline(activeIncidentPortId,[]);renderIncidentModal(activeIncidentPortId)};if(exportIncidentTimeline)exportIncidentTimeline.onclick=()=>{if(!activeIncidentPortId)return;const item=meta.get(activeIncidentPortId)||{},payload={generated_at:new Date().toISOString(),port_id:activeIncidentPortId,device:item.device_label||item.hostname||'',interface:item.ifName||'',health_score:document.getElementById('port-'+activeIncidentPortId)?.dataset.healthScore||100,events:loadIncidentTimeline(activeIncidentPortId)};const blob=new Blob([JSON.stringify(payload,null,2)],{type:'application/json'}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='incident_port_'+activeIncidentPortId+'_'+Date.now()+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)};document.addEventListener('keydown',e=>{if(e.key==='Escape'&&incidentModal&&incidentModal.classList.contains('open'))closeIncident()});
function closeWidgetFullscreen(){document.body.classList.remove('widget-fullscreen');document.querySelectorAll('.widget-expanded').forEach(c=>c.classList.remove('widget-expanded'));setTimeout(()=>window.dispatchEvent(new Event('resize')),100)}if(exitWidgetFullscreen)exitWidgetFullscreen.onclick=closeWidgetFullscreen;document.addEventListener('keydown',e=>{if(e.key==='Escape'&&document.body.classList.contains('widget-fullscreen'))closeWidgetFullscreen()});

function applyAutoFit(){const enabled=localStorage.getItem('bw_auto_fit')!=='0';document.body.classList.toggle('auto-fit',enabled);if(autoFitBtn){autoFitBtn.classList.toggle('active',enabled);autoFitBtn.textContent=enabled?'Auto Fit On':'Auto Fit Off';}setTimeout(()=>window.dispatchEvent(new Event('resize')),80)}
if(autoFitBtn)autoFitBtn.onclick=()=>{localStorage.setItem('bw_auto_fit',document.body.classList.contains('auto-fit')?'0':'1');applyAutoFit()};
applyAutoFit();
if(focusBtn)focusBtn.onclick=()=>{const on=document.body.classList.toggle('focus-dashboard');focusBtn.classList.toggle('active',on);focusBtn.textContent=on?'Exit Focus':'Focus';localStorage.setItem('bw_focus',on?'1':'0');setTimeout(()=>window.dispatchEvent(new Event('resize')),100)};
if(localStorage.getItem('bw_focus')==='1'){document.body.classList.add('focus-dashboard');if(focusBtn){focusBtn.classList.add('active');focusBtn.textContent='Exit Focus';}}
document.addEventListener('keydown',e=>{if(e.key.toLowerCase()==='f'&&!/input|select|textarea/i.test(document.activeElement.tagName)){e.preventDefault();if(focusBtn)focusBtn.click()}if(e.key.toLowerCase()==='r'&&!/input|select|textarea/i.test(document.activeElement.tagName)){e.preventDefault();if(manualRefreshBtn)manualRefreshBtn.click()}if(e.key==='Escape'&&document.body.classList.contains('focus-dashboard')){if(focusBtn)focusBtn.click()}});

if(densityBtn)densityBtn.onclick=()=>{document.body.classList.toggle('compact-dashboard');const on=document.body.classList.contains('compact-dashboard');densityBtn.classList.toggle('active',on);densityBtn.textContent=on?'Comfort View':'Compact';localStorage.setItem('bw_compact',on?'1':'0');setTimeout(()=>window.dispatchEvent(new Event('resize')),80)};
if(localStorage.getItem('bw_compact')==='1'){document.body.classList.add('compact-dashboard');if(densityBtn){densityBtn.classList.add('active');densityBtn.textContent='Comfort View';}}
if(pauseLiveBtn)pauseLiveBtn.onclick=()=>{livePaused=!livePaused;pauseLiveBtn.classList.toggle('active',livePaused);pauseLiveBtn.textContent=livePaused?'Resume Live':'Pause Live';refreshRemaining=Math.max(1,Math.round(REFRESH_MS/1000));updateCommandDeck(true)};
if(manualRefreshBtn)manualRefreshBtn.onclick=async()=>{manualRefreshBtn.textContent='Refreshing';manualRefreshBtn.disabled=true;await tick();manualRefreshBtn.textContent='Refresh';manualRefreshBtn.disabled=false;refreshRemaining=Math.max(1,Math.round(REFRESH_MS/1000));};
setInterval(()=>{if(!livePaused&&currentRange==='live'){refreshRemaining--;if(refreshRemaining<=0)refreshRemaining=Math.max(1,Math.round(REFRESH_MS/1000));}updateCommandDeck(true)},1000);
async function tick(){const tickStart=performance.now();clock.textContent=new Date().toLocaleString('id-ID');try{const renderStart=performance.now();await Promise.all([loadSummary(),loadPorts()]);perfMetrics.render=Math.round(performance.now()-renderStart);refreshRemaining=Math.max(1,Math.round(REFRESH_MS/1000));updateCommandDeck(true);setTimeout(()=>loadTopTraffic().catch(e=>console.warn('top traffic async gagal',e)),50)}catch(e){lastUpdate.textContent='ERROR: '+e.message;updateCommandDeck(false);console.error(e)}finally{perfMetrics.tick=Math.round(performance.now()-tickStart);updatePerformanceUI()}} setInterval(()=>clock.textContent=new Date().toLocaleString('id-ID'),1000); setInterval(()=>{if(currentRange==='live'&&!livePaused)tick()},REFRESH_MS); window.addEventListener('resize',()=>document.querySelectorAll('.card').forEach(c=>{const h=hist.get(Number(c.id.replace('port-',''))); if(h)draw(c.querySelector('canvas'),h)})); if(IS_ADMIN){const mub=document.getElementById('manageUsersBtn'),cum=document.getElementById('closeUserModal'),cub=document.getElementById('createUserBtn');if(mub)mub.onclick=()=>{userModal.classList.add('open');userModal.setAttribute('aria-hidden','false');loadUsers()};if(cum)cum.onclick=()=>{userModal.classList.remove('open');userModal.setAttribute('aria-hidden','true')};if(cub)cub.onclick=createUser;if(userModal)userModal.addEventListener('click',e=>{if(e.target===userModal)cum.click()});}
applyTheme(); if(!IS_ADMIN){document.querySelectorAll('.admin-only').forEach(e=>e.remove());} const initialProfileOption=profileSelect&&profileSelect.options[profileSelect.selectedIndex]; if(initialProfileOption&&initialProfileOption.value&&initialProfileOption.dataset.ids){currentProfile=initialProfileOption.value;selectedIds=JSON.parse(initialProfileOption.dataset.ids||'[]').map(Number).filter(x=>x>0);localStorage.setItem('bw_profile',currentProfile);localStorage.setItem('bw_selected_ports',JSON.stringify(selectedIds));const vps=document.getElementById('viewerProfileStatus');if(vps)vps.textContent='Aktif: '+currentProfile+' ('+selectedIds.length+' port)';} initTime(); if(search){search.addEventListener('focus',()=>{if(!portSelect.options.length||portSelect.options.length<=1)searchPorts()},{once:true});} loadGroups(); loadProfiles().then(()=>loadSavedIds()).then(()=>{renderChips(); tick();}).catch(e=>{lastUpdate.textContent='INIT ERROR: '+e.message;updateCommandDeck(false);console.error('dashboard init gagal',e)});
</script></body></html>
