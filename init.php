<?php

require_once('vendor/autoload.php');
$config = require_once('src/settings.php');


unlink('database/database.db');
mkdir('database');
system('sqlite3 database/database.db < schema.sql');
chmod('database', 0777);
chmod('database/database.db', 0777);

$db = new Medoo\Medoo($config['settings']['db']);
$db->insert('competition', [
    'name' => 'CTF',
    'start_at' => strtotime('2018-01-01 09:00:00 JST'),
    'end_at' => strtotime('2018-12-31 09:00:00 JST'),
    'enabled' => 0
]);

$db->insert('users', [
    'name' => 'admin',
    'password_hash' => password_hash('mogumogutakoyaki', PASSWORD_DEFAULT),
    'team_id' => 0,
    'is_admin' => 1,
]);