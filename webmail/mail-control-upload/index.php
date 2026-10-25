<?php
/** Shared upload policy, integrated through SnappyMail's public plugin hooks. */
class MailControlUploadPlugin extends \RainLoop\Plugins\AbstractPlugin
{
    const NAME = 'Mail Control Upload', AUTHOR = 'Mail Control', VERSION = '1.0.1',
        RELEASE = '2026-10-25', REQUIRED = '2.38.2', LICENSE = 'MIT',
        DESCRIPTION = 'Shared attachment limits and visible network upload progress';

    public function Init(): void
    {
        $this->addJs('upload.js');
        $this->addCss('upload.css');
        $this->addHook('filter.application-config', 'applyConfig');
        $this->addHook('filter.app-data', 'appData');
        $this->addHook('filter.upload-response', 'recordUpload');
        $this->addHook('filter.action-params', 'checkParams');
        $this->addHook('filter.send-message', 'checkMessage');
        $this->addHook('filter.smtp-message-stream', 'checkStream');
        $this->addJsonHook('MailControlUploadPolicy', 'policyResponse');
        $this->addJsonHook('MailControlUploadProgress', 'progressResponse');
    }

    public function policy(): array
    {
        $path = \getenv('MAIL_CONTROL_UPLOAD_POLICY') ?: '/data/mail-control-upload-policy.json';
        $data = \is_readable($path) ? \json_decode((string) \file_get_contents($path), true) : null;
        $policy = ['single_mb' => 12, 'total_mb' => 24, 'max_count' => 12, 'message_mb' => 200];
        if (\is_array($data)) {
            foreach ($policy as $key => $default) {
                $maximum = $key === 'message_mb' ? 200 : 100;
                $value = $data[$key] ?? $default;
                if (\is_numeric($value) && \is_finite((float)$value) && (float)$value >= 1 && (float)$value <= $maximum) {
                    $policy[$key] = (int)$value;
                }
            }
        }
        $policy['single_mb'] = \min($policy['single_mb'], $policy['total_mb']);
        return $policy;
    }

    public function applyConfig(\RainLoop\Config\Application $config): void
    {
        $config->Set('webmail', 'attachment_size_limit', $this->policy()['single_mb']);
    }

    public function FilterAppDataPluginSection(bool $admin, bool $auth, array &$config): void
    {
        if (!$admin && $auth) { $config['policy'] = $this->policy(); }
    }

    public function appData(bool $admin, array &$data): void
    {
        // The composer captures this once; live policy is enforced on each request.
        if (!$admin && !empty($data['Auth'])) { $data['attachmentLimit'] = 100 * 1048576; }
    }

    public function recordUpload(array &$response): void
    {
        $file = $response['Result']['Attachment'] ?? null;
        if (!\is_array($file) || empty($file['tempName'])) { return; }
        $actions = $this->Manager()->Actions();
        $account = $actions->getAccountFromToken(false);
        if (!$account) { return; }
        $path = $actions->FilesProvider()->GetFileName($account, (string)$file['tempName']);
        if (!$path || !\is_file($path)) { return; }
        $dir = \getenv('MAIL_CONTROL_UPLOAD_EVENTS') ?: '/data/mail-control-upload-events';
        if (!\is_dir($dir) && !@\mkdir($dir, 0700, true)) { return; }
        $target = $dir . '/' . \hash('sha256', $path) . '.json';
        $record = ['source' => 'webmail', 'path' => $path, 'filename' => (string)$file['name'],
            'mailbox' => $account->Email(), 'size' => (int)$file['size'], 'mtime' => (int)\filemtime($path)];
        $temp = @\tempnam($dir, '.upload-');
        if ($temp !== false) {
            if (@\file_put_contents($temp, \json_encode($record, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX) !== false) {
                @\chmod($temp, 0600);
                @\rename($temp, $target);
            }
            if (\is_file($temp)) { @\unlink($temp); }
        }
    }

    public function policyResponse()
    {
        $this->Manager()->Actions()->getAccountFromToken();
        return $this->jsonResponse(__FUNCTION__, $this->policy());
    }

    public function progressResponse()
    {
        // Observability only: client-reported values never authorize sending,
        // bypass limits, establish file ownership, or trigger file deletion.
        $actions = $this->Manager()->Actions();
        $account = $actions->getAccountFromToken();
        $id = (string)$actions->GetActionParam('id', '');
        $status = (string)$actions->GetActionParam('status', 'uploading');
        if (!\preg_match('/^[a-zA-Z0-9_.-]{1,100}$/D', $id) ||
            !\in_array($status, ['uploading', 'processing', 'completed', 'failed', 'cancelled'], true)) {
            throw new \InvalidArgumentException('上传进度格式无效');
        }
        $sizes = [];
        foreach (['total', 'received', 'size'] as $key) {
            $value = $actions->GetActionParam($key, 0);
            if (!\is_numeric($value) || !\is_finite((float)$value) || (float)$value < 0 || (float)$value > 128 * 1048576) {
                throw new \InvalidArgumentException('上传进度大小无效');
            }
            $sizes[$key] = (int)$value;
        }
        $sizes['received'] = \min($sizes['received'], $sizes['total']);
        $filename = \preg_replace('/[\x00-\x1f\x7f\\\\\/]+/u', '_', (string)$actions->GetActionParam('filename', ''));
        $filename = \function_exists('mb_strcut') ? \mb_strcut($filename ?: '', 0, 255, 'UTF-8') : \substr($filename ?: '', 0, 255);
        $dir = \getenv('MAIL_CONTROL_UPLOAD_EVENTS') ?: '/data/mail-control-upload-events';
        if (!\is_dir($dir) && !@\mkdir($dir, 0700, true)) {
            return $this->jsonResponse(__FUNCTION__, ['accepted' => false]);
        }
        $lock = @\fopen($dir . '/.progress.lock', 'c');
        if (!$lock || !@\flock($lock, LOCK_EX | LOCK_NB)) {
            if ($lock) { \fclose($lock); }
            return $this->jsonResponse(__FUNCTION__, ['accepted' => false]);
        }
        try {
            @\chmod($dir . '/.progress.lock', 0600);
            $key = \hash('sha256', $account->Email() . "\x00" . $id);
            $target = $dir . '/progress-' . $key . '.json';
            $now = \time();
            $previous = !\is_link($target) && \is_file($target) && \filesize($target) < 8192
                ? \json_decode((string)\file_get_contents($target), true) : null;
            $record = ['id' => 'webmail-' . $key, 'source' => 'webmail', 'actor' => $account->Email(),
                'total' => $sizes['total'], 'received' => $sizes['received'], 'status' => $status,
                'files' => [['filename' => $filename, 'size' => $sizes['size']]], 'error' => '',
                'created_at' => \is_array($previous) ? (int)($previous['created_at'] ?? $now) : $now,
                'updated_at' => $now, 'reported_by' => 'client'];
            $temp = @\tempnam($dir, '.progress-');
            if ($temp !== false) {
                if (@\file_put_contents($temp, \json_encode($record, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX) !== false) {
                    @\chmod($temp, 0600);
                    @\rename($temp, $target);
                }
                if (\is_file($temp)) { @\unlink($temp); }
            }
            // Keep only bounded metadata; never inspect/remove attachment files.
            $entries = [];
            foreach (\glob($dir . '/progress-*.json') ?: [] as $path) {
                if (\is_link($path) || !\preg_match('/^progress-[a-f0-9]{64}\.json$/D', \basename($path))) { continue; }
                $time = (int)@\filemtime($path);
                if ($time < $now - 86400) { @\unlink($path); }
                else { $entries[$path] = $time; }
            }
            if (\count($entries) > 1000) {
                \asort($entries, SORT_NUMERIC);
                foreach (\array_slice(\array_keys($entries), 0, \count($entries) - 1000) as $path) { @\unlink($path); }
            }
            return $this->jsonResponse(__FUNCTION__, ['accepted' => true]);
        } finally { \flock($lock, LOCK_UN); \fclose($lock); }
    }

    private function fail(string $message): void
    {
        throw new \RainLoop\Exceptions\ClientException(\RainLoop\Notifications::CantSendMessage, null, $message);
    }

    private function validateSizes(array $sizes): void
    {
        $policy = $this->policy();
        if (\count($sizes) > $policy['max_count']) {
            $this->fail('附件数量不能超过 ' . $policy['max_count'] . ' 个');
        }
        $total = 0;
        foreach ($sizes as $size) {
            if ($size < 0 || $size > $policy['single_mb'] * 1048576) {
                $this->fail('单个附件不能超过 ' . $policy['single_mb'] . ' MB');
            }
            $total += $size;
        }
        if ($total > $policy['total_mb'] * 1048576) {
            $this->fail('附件总大小不能超过 ' . $policy['total_mb'] . ' MB');
        }
    }

    public function checkParams(string $method, array &$params): void
    {
        if ($method !== 'DoSendMessage') { return; }
        $actions = $this->Manager()->Actions();
        $account = $actions->getAccountFromToken();
        $attachments = $params['attachments'] ?? [];
        if (!\is_array($attachments)) { $this->fail('附件格式无效'); }
        $sizes = [];
        foreach ($attachments as $key => $value) {
            if (!\is_string($key) || $key === '' || !\is_array($value)) { $this->fail('附件格式无效'); }
            if (!$actions->FilesProvider()->FileExists($account, $key)) {
                $this->fail('附件临时文件已失效，请重新上传');
            }
            $sizes[] = $actions->FilesProvider()->FileSize($account, $key);
        }
        // Inline pasted images become MIME attachments too, including encrypted mail.
        if (!empty($params['html']) && \preg_match_all('~data:image/[a-zA-Z0-9.+-]+;base64,([a-zA-Z0-9+/=\r\n]+)~', (string)$params['html'], $matches)) {
            foreach (\array_unique($matches[1]) as $encoded) {
                $raw = \base64_decode($encoded, true);
                if ($raw === false) { $this->fail('内嵌图片格式无效'); }
                $sizes[] = \strlen($raw);
            }
        }
        $this->validateSizes($sizes);
    }

    public function checkMessage(\MailSo\Mime\Message $message): void
    {
        $sizes = [];
        foreach ($message->Attachments() as $attachment) {
            $stat = \fstat($attachment->Resource());
            if ($stat === false) { $this->fail('无法读取附件大小'); }
            $sizes[] = (int)$stat['size'];
        }
        $this->validateSizes($sizes);
    }

    public function checkStream($account, &$stream, int &$size): void
    {
        if ($size > $this->policy()['message_mb'] * 1048576) {
            $this->fail('编码后的整封邮件超过邮件服务器大小限制');
        }
    }
}
