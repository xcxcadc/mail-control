<?php
// Run: php webmail/test_policy.php. No SnappyMail/bootstrap or live account.
namespace RainLoop\Plugins {
    abstract class AbstractPlugin {
        public $manager;
        public function Manager() { return $this->manager; }
        protected function jsonResponse($name,$data) { return ['Result'=>$data]; }
    }
}
namespace RainLoop\Config {
    class Application { public array $values = []; public function Set($a,$b,$c) { $this->values[$a][$b] = $c; } }
}
namespace RainLoop { class Notifications { const CantSendMessage = 302; } }
namespace RainLoop\Exceptions {
    class ClientException extends \RuntimeException { public function __construct($code,$prev,$message) {parent::__construct($message,$code);} }
}
namespace MailSo\Mime {
    class Message {
        public array $items;
        public function __construct(array $sizes) { $this->items = array_map(fn($size) => new FakeAttachment($size), $sizes); }
        public function Attachments() { return $this->items; }
    }
    class FakeAttachment {
        private $stream;
        public function __construct($size) { $this->stream = tmpfile(); ftruncate($this->stream,$size); }
        public function Resource() { return $this->stream; }
    }
}
namespace {
    require __DIR__ . '/mail-control-upload/index.php';
    function demand($ok, $message) { if (!$ok) throw new \RuntimeException($message); }
    function rejected($callback) { try { $callback(); } catch (\RainLoop\Exceptions\ClientException $e) { return; } throw new \RuntimeException('limit was bypassed'); }
    $file = tempnam(sys_get_temp_dir(), 'mc-upload-policy-');
    $events = sys_get_temp_dir() . '/mc-upload-progress-' . bin2hex(random_bytes(6));
    putenv('MAIL_CONTROL_UPLOAD_POLICY=' . $file);
    putenv('MAIL_CONTROL_UPLOAD_EVENTS=' . $events);
    try {
        file_put_contents($file, json_encode(['single_mb'=>2,'total_mb'=>3,'max_count'=>2,'message_mb'=>200]));
        $plugin = new MailControlUploadPlugin();
        $config = new \RainLoop\Config\Application();
        $plugin->applyConfig($config);
        demand($config->values['webmail']['attachment_size_limit'] === 2, 'single limit not applied');
        $plugin->checkMessage(new \MailSo\Mime\Message([1048576, 1048576]));
        rejected(fn() => $plugin->checkMessage(new \MailSo\Mime\Message([2097153])));
        rejected(fn() => $plugin->checkMessage(new \MailSo\Mime\Message([2097152, 2097152])));
        rejected(fn() => $plugin->checkMessage(new \MailSo\Mime\Message([1,1,1])));
        file_put_contents($file, json_encode(['single_mb'=>4,'total_mb'=>8,'max_count'=>4,'message_mb'=>200]));
        $plugin->checkMessage(new \MailSo\Mime\Message([2097153,2097153]));
        $stream = null; $size = 200 * 1048576;
        $plugin->checkStream(null, $stream, $size);
        $size++;
        rejected(function() use ($plugin, &$stream, &$size) { $plugin->checkStream(null, $stream, $size); });
        file_put_contents($file, '{broken');
        demand($plugin->policy()['single_mb'] === 12, 'invalid policy fallback');
        $account = new class {public function Email() {return 'fixture@example.test';}};
        $actions = new class($account) {
            public array $params=[];
            public bool $authenticated=true;
            private $account;
            public function __construct($account) {$this->account=$account;}
            public function getAccountFromToken() {if(!$this->authenticated)throw new \RuntimeException('auth required');return $this->account;}
            public function GetActionParam($key,$default) {return $this->params[$key]??$default;}
        };
        $plugin->manager=new class($actions) {
            private $actions;
            public function __construct($actions) {$this->actions=$actions;}
            public function Actions() {return $this->actions;}
        };
        $actions->params=['id'=>'jua-test-1','filename'=>'fixture.txt','size'=>1024,'received'=>512,'total'=>1024,'status'=>'uploading'];
        $response=$plugin->progressResponse();
        demand($response['Result']['accepted']===true,'progress not recorded');
        $paths=glob($events.'/progress-*.json');
        demand(count($paths)===1,'progress filename invalid');
        $record=json_decode(file_get_contents($paths[0]),true);
        demand($record['actor']==='fixture@example.test'&&$record['received']===512&&$record['reported_by']==='client','progress fields invalid');
        $actions->params['received']=2000;
        $actions->params['status']='completed';
        $plugin->progressResponse();
        demand(json_decode(file_get_contents($paths[0]),true)['received']===1024,'progress clamp failed');
        $actions->params['total']=129*1048576;
        try {$plugin->progressResponse();throw new \RuntimeException('oversized progress accepted');}catch(\InvalidArgumentException $expected){}
        $actions->params['total']=1024;$actions->params['id']='../bad';
        try {$plugin->progressResponse();throw new \RuntimeException('bad id accepted');}catch(\InvalidArgumentException $expected){}
        $actions->params['id']='jua-test-1';$actions->authenticated=false;
        try {$plugin->progressResponse();throw new \RuntimeException('unauthenticated progress accepted');}catch(\RuntimeException $expected){demand($expected->getMessage()==='auth required','auth bypassed');}
        echo "PASS: plugin live size/count/total/MIME guards and authenticated bounded upload progress\n";
    } finally {
        unlink($file);
        foreach(array_merge(glob($events.'/*')?:[],glob($events.'/.*')?:[]) as $path)
            if(is_file($path))unlink($path);
        if(is_dir($events))rmdir($events);
    }
}
