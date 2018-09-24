<?php

use Slim\Http\Request;
use Slim\Http\Response;

date_default_timezone_set("Asia/Tokyo");

function getSubmissions($db) {
    $submissions = $db->select('submissions', [
        '[><]users' => ['u_id' => 'id'],
        '[><]teams' => ['users.team_id' => 'id'],
        '[><]challenges' => ['p_id' => 'id'],
    ], [
        'teams.name(team_name)', 'team_id', 'submissions.point(point)', 'created_at', 'challenges.name(challenge_name)'
    ], [
        'is_correct' => 1,
        'submissions.point[!]' => 0,
        'ORDER' => 'created_at',
    ]);

    return $submissions;
}
function getTeam($db, $team_id)
{
    $team = $db->get('teams', '*', ['id' => $team_id]);
    if (!$team) {
        return [];
    }
    $members = $db->select('users', '*', [
        'team_id' => $team['id'],
    ]);

    $solved = $db->select('submissions', 'p_id', [
        'is_correct' => 1,
        'u_id' => $db->select('users', 'id', [
            'team_id' => $team['id'],
        ]),
    ]);

    $solved = $db->select('challenges', '*', [
        'id' => $solved,
    ]);

    return array_merge($team, [
        'members' => $members,
        'solved' => $solved,
    ]);
}

function getUser($db, $user_id)
{
    $user = $db->get('users', '*', ['id' => $user_id]);
    $team = getTeam($db, $user['team_id']);
    $solved = $db->select('submissions', '*', [
        'is_correct' => 1,
        'u_id' => $user['id'],
    ]);

    return array_merge($user, [
        'team' => $team,
        'solved' => $solved,
    ]);
}

function getChallenge($db, $id)
{
    $challenge = $db->get('challenges', '*', ['id' => $id]);
    $cat = $db->get('categories', 'name', ['id' => $challenge['c_id']]);

    $challenge['category'] = $cat;
    return $challenge;
}

function getChallenges($db, $open_only)
{
    $cond = $open_only ? ' where is_open = 1' : '';
    $challenges = $db->query('select ' .
        'challenges.id as id, challenges.name as name, description, flag, point, is_open, categories.name as category, ' .
        '(select count(*) from submissions where is_correct = 1 and p_id = challenges.id) as solved ' .
        'from challenges inner join categories on challenges.c_id = categories.id ' . $cond)->fetchAll();

    return $challenges;
}

function descriptionFilter($s, $req, $app)
{
    $s = preg_replace_callback('/{{url}}\((.+)\)/', function ($m) use ($req) {
        $base = $req->getUri()->getBaseUrl();
        $path = $m[1];
        $file = basename($path);
        return "<a href='$base$path'>$file</a>";
    }, $s);
    $s = preg_replace_callback('/{{host}}\((.+)\)/', function ($m) use ($req) {
        $scheme = $req->getUri()->getScheme();
        $base = $req->getUri()->getHost();
        $path = $m[1];
        $file = basename($path);
        return "<a href='$scheme://$base$path'>$file</a>";
    }, $s);
    return $s;
}

$app->add(function ($request, $response, $next) use ($container) {
    if (isset($_SESSION['user_id'])) {
        $user = getUser($this->db, $_SESSION['user_id']);
        $ctf = $this->db->get('competition', '*');
        $container['view']->getEnvironment()->addGlobal("user", $user);
        $container['view']->getEnvironment()->addGlobal("ctf", $ctf);
        $request = $request->withAttribute('user', $user);
    }
    return $next($request, $response);
});

$authorization = function ($admin_only = false) use ($container) {
    return function ($request, $response, $next) use ($admin_only, $container) {
        if (!isset($_SESSION['user_id'])) {
            $container['flash']->addMessage('errors', 'Login required');
            return $response->withRedirect($this->router->pathFor('login'));
        }

        $user = getUser($container->db, $_SESSION['user_id']);
        if ($admin_only && $user['is_admin'] == 0) {
            $container['flash']->addMessage('errors', 'Administrator pemission is required');
            return $response->withRedirect($this->router->pathFor('login'));
        }

        return $next($request, $response);
    };
};

$time_range = function ($request, $response, $next) use ($container) {
    $competition = $container['db']->select('competition', '*')[0];
    $now = time();

    if (!$competition['enabled'] || $now < $competition['start_at'] || $competition['end_at'] < $now) {
        $container['flash']->addMessage('errors', 'Contest outdated');
        return $response->withRedirect($this->router->pathFor('index'));
    }
    return $next($request, $response);
};

$app->get('/', function (Request $request, Response $response, array $args) {
    $r = $this->db->get('competition', '*');
    return $this->view->render($response, 'index.html', ['ctf' => $r]);
})->setName('index');

$app->get('/login', function (Request $request, Response $response, array $args) {
    return $this->view->render($response, 'login.html');
})->setName('login');

$app->get('/register', function (Request $request, Response $response, array $args) {
    return $this->view->render($response, 'register.html');
})->setName('register');

$app->post('/register-team', function (Request $request, Response $response, array $args) use ($app) {
    $postParams = $request->getParsedBody();

    if (!isset($postParams['username']) || !preg_match('/^[A-Za-z0-9-_]{1,30}$/', $postParams['username'])) {
        $this->flash->addMessage('errors', 'username is invalid');
        return $response->withRedirect($this->router->pathFor('register'));
    }
    if (!isset($postParams['password']) || empty($postParams['password'])) {
        $this->flash->addMessage('errors', 'password is invalid');
        return $response->withRedirect($this->router->pathFor('register'));
    }
    if (!isset($postParams['team']) || !preg_match('/^[A-Za-z0-9-_]{1,30}$/', $postParams['team'])) {
        $this->flash->addMessage('errors', 'team name is invalid');
        return $response->withRedirect($this->router->pathFor('register'));
    }

    $username = $postParams['username'];
    $password = $postParams['password'];
    $team = $postParams['team'];

    try {
        $this->db->insert('teams', [
            'name' => $team,
            'token' => sha1($team . time()),
        ]);
    } catch (PDOException $e) {
        $this->flash->addMessage('errors', 'failed to create new team' . var_export($this->db->error(), true));
        return $response->withRedirect($this->router->pathFor('register'));
    }
    $team_id = $this->db->id();

    try {
        $this->db->insert('users', [
            'name' => $username,
            'password_hash' => password_hash($password, PASSWORD_DEFAULT),
            'team_id' => $team_id,
        ]);
    } catch (PDOException $e) {
        $this->db->delete('teams', ['id' => $team_id]);
        $this->flash->addMessage('errors', 'failed to register new user');
        return $response->withRedirect($this->router->pathFor('register'));
    }

    $_SESSION['user_id'] = $this->db->id();

    $this->flash->addMessage('messages', 'Hello ' . $username);
    return $response->withRedirect($this->router->pathFor('login'));
});

$app->post('/register-user', function (Request $request, Response $response, array $args) use ($app) {
    $postParams = $request->getParsedBody();

    if (!isset($postParams['username']) || !preg_match('/^[A-Za-z0-9-_]{1,30}$/', $postParams['username'])) {
        $this->flash->addMessage('errors', 'username is invalid');
        return $response->withRedirect($this->router->pathFor('register'));
    }
    if (!isset($postParams['password']) || empty($postParams['password'])) {
        $this->flash->addMessage('errors', 'password is invalid');
        return $response->withRedirect($this->router->pathFor('register'));
    }
    if (!isset($postParams['team'])) {
        $this->flash->addMessage('errors', 'team token is invalid');
        return $response->withRedirect($this->router->pathFor('register'));
    }

    $username = $postParams['username'];
    $password = $postParams['password'];
    $team = $postParams['team'];

    if (!$this->db->has('teams', ['token' => $team])) {
        $this->flash->addMessage('errors', 'team token is invalid');
        return $response->withRedirect($this->router->pathFor('register'));
    }

    try {
        $this->db->insert('users', [
            'name' => $username,
            'password_hash' => password_hash($password, PASSWORD_DEFAULT),
            'team_id' => $this->db->get('teams', 'id', ['token' => $team]),
        ]);
    } catch (PDOException $e) {
        if ($this->db->error()) {
            $this->flash->addMessage('errors', 'failed to register new user');
            return $response->withRedirect($this->router->pathFor('register'));
        }
    }

    $this->flash->addMessage('messages', 'register succeeded');
    return $response->withRedirect($this->router->pathFor('login'));
});

$app->post('/login', function (Request $request, Response $response, array $args) use ($app) {
    $postParams = $request->getParsedBody();

    // check required paramter
    if (!isset($postParams['username'])) {
        $this->flash->addMessage('errors', 'Parameter username is required');
        return $response->withRedirect($this->router->pathFor('login'));
    }
    if (!isset($postParams['password'])) {
        $this->flash->addMessage('errors', 'Parameter password is required');
        return $response->withRedirect($this->router->pathFor('login'));
    }

    $username = $postParams['username'];
    $password = $postParams['password'];

    $user = $this->db->get("users", '*', ['name' => $username]);
    if (!$user) {
        $this->flash->addMessage('errors', "User $username does not exist.");
        return $response->withRedirect($this->router->pathFor('login'));
    }

    if (!password_verify($password, $user['password_hash'])) {
        $this->flash->addMessage('errors', "Password for user $username does not correct.");
        return $response->withRedirect($this->router->pathFor('login'));
    }

    $_SESSION['user_id'] = $user['id'];

    $this->flash->addMessage('messages', 'Hello ' . $username);
    return $response->withRedirect($this->router->pathFor('team', ['id' => $user['team_id']]));
});

$app->post('/logout', function (Request $request, Response $response, array $args) {
    unset($_SESSION['user_id']);
    return $response->withRedirect($this->router->pathFor('login'));
})->setName('login');

$app->get('/team/{id}', function (Request $request, Response $response, array $args) {
    $id = $args['id'];
    $team = getTeam($this->db, $id);
    return $this->view->render($response, 'team.html', ['team' => $team]);
})->setName('team');

$app->get('/challenges', function (Request $request, Response $response, array $args) {
    $challenges = getChallenges($this->db, true);

    return $this->view->render($response, 'challenges.html', ['challenges' => $challenges]);
})->setName('challenges')->add($authorization());

$app->get('/challenge/{id}', function (Request $request, Response $response, array $args) {
    $challenge = getChallenge($this->db, $args['id']);
    $challenge['description'] = descriptionFilter($challenge['description'], $request, $this);

    return $this->view->render($response, 'challenge.html', ['challenge' => $challenge]);
})->setName('challenge')->add($authorization())->add($time_range);

$app->post('/submit/{id}', function (Request $request, Response $response, array $args) {
    $postParams = $request->getParsedBody();
    $flag = $postParams['flag'] ?? '';
    $user = $request->getAttribute('user');

    $challenge = getChallenge($this->db, $args['id']);
    if (!$challenge || !$challenge['is_open']) {
        $this->flash->addMessage('errors', 'Challenge does not exist');
        return $response->withRedirect($this->router->pathFor('challenges'));
    }

    $is_correct = 0;
    $point = 0;
    if ($challenge['flag'] === trim($flag)) {
        $is_correct = 1;
        $team_solved = array_column($user['team']['solved'], 'id');
        if (array_search($challenge['id'], $team_solved) === false) {
            $point = $challenge['point'];
            $this->flash->addMessage('messages', "Correct! You got $point points");
        } else {
            $this->flash->addMessage('messages', "Your team already solved this challenge.");

        }
    } else {
        $this->flash->addMessage('errors', 'Wrong...');
    }

    $this->db->insert('submissions', [
        'p_id' => $challenge['id'],
        'u_id' => $user['id'],
        'flag' => $flag,
        'is_correct' => $is_correct,
        'point' => $point,
        'created_at' => time(),
    ]);

    return $response->withRedirect($this->router->pathFor('challenge', ['id' => $args['id']]));
})->add($authorization())->add($time_range);

$app->get('/scores', function (Request $request, Response $response, array $args) {
    $teams = $this->db->select('teams', '*');
    $submissions = getSubmissions($this->db);

    for ($i = 0; $i < count($teams); $i++) {
        $teams[$i]['point'] = 0;
    }
    foreach ($submissions as $s) {
        $teams[$s['team_id'] - 1]['point'] += $s['point'];
    }
    
    return $this->view->render($response, 'scores.html', ['teams' => $teams, 'submissions' => $submissions]);
})->setName('scores');

$app->group('/admin', function () use ($app, $container) {
    $app->get('', function (Request $request, Response $response, array $args) {
        return $this->view->render($response, 'admin.html');
    });

    $app->get('/categories', function (Request $request, Response $response, array $args) {
        $categories = $this->db->select('categories', '*');
        return $this->view->render($response, 'admin/categories.html', ['categories' => $categories]);
    })->setName('admin/categories');

    $app->post('/categories', function (Request $request, Response $response, array $args) {
        $postParams = $request->getParsedBody();
        if (!isset($postParams['name'])) {
            $this->flash->addMessage('errors', 'Parameter name is required');
            return $response->withRedirect($this->router->pathFor('admin/categories'));
        }
        try {
            $this->db->insert('categories', ['name' => $postParams['name']]);
        } catch (PDOException $e) {
            $this->flash->addMessage('errors', $e->getMessage());
        }
        return $response->withRedirect($this->router->pathFor('admin/categories'));
    });

    $app->get('/category/{id}', function (Request $request, Response $response, array $args) {
        $category = $this->db->get('categories', '*', ['id' => $args['id']]);
        return $this->view->render($response, 'admin/category.html', ['category' => $category]);
    })->setName('admin/category');

    $app->post('/category/{id}', function (Request $request, Response $response, array $args) {
        $postParams = $request->getParsedBody();
        if (!isset($postParams['name'])) {
            $this->flash->addMessage('errors', 'Parameter name is required');
            return $response->withRedirect($this->router->pathFor('admin/category', ['id' => $args['id']]));
        }
        $this->db->update('categories', ['name' => $postParams['name']], ['id' => $args['id']]);
        return $response->withRedirect($this->router->pathFor('admin/category', ['id' => $args['id']]));
    });

    $app->post('/category/{id}/delete', function (Request $request, Response $response, array $args) {
        $category = $this->db->delete('categories', ['id' => $args['id']]);
        return $response->withRedirect($this->router->pathFor('admin/categories'));
    });

    $app->get('/challenges', function (Request $request, Response $response, array $args) {
        $challenges = getChallenges($this->db, false);
        $categories = $this->db->select('categories', '*');
        return $this->view->render($response, 'admin/challenges.html', ['challenges' => $challenges, 'categories' => $categories]);
    })->setName('admin/challenges');

    $app->post('/challenges', function (Request $request, Response $response, array $args) {
        $postParams = $request->getParsedBody();
        if (!isset($postParams['name'])) {
            $this->flash->addMessage('errors', 'Parameter name is invalid');
            return $response->withRedirect($this->router->pathFor('admin/challenges'));
        }
        if (!isset($postParams['description'])) {
            $this->flash->addMessage('errors', 'Parameter description is invalid');
            return $response->withRedirect($this->router->pathFor('admin/challenges'));
        }
        if (!isset($postParams['flag'])) {
            $this->flash->addMessage('errors', 'Parameter flag is invalid');
            return $response->withRedirect($this->router->pathFor('admin/challenges'));
        }
        if (!isset($postParams['point']) || !preg_match('/^[0-9]+$/', $postParams['point'])) {
            $this->flash->addMessage('errors', 'Parameter point is invalid');
            return $response->withRedirect($this->router->pathFor('admin/challenges'));
        }
        if (!isset($postParams['category']) || !$this->db->has('categories', ['id' => $postParams['category']])) {
            $this->flash->addMessage('errors', 'Parameter category is invalid');
            return $response->withRedirect($this->router->pathFor('admin/challenges'));
        }

        try {
            $this->db->insert('challenges', [
                'name' => $postParams['name'],
                'description' => $postParams['description'],
                'flag' => $postParams['flag'],
                'point' => $postParams['point'],
                'c_id' => $postParams['category'],
                'is_open' => isset($postParams['is_open']) ? 1 : 0,
            ]);
        } catch (PDOException $e) {
            $this->flash->addMessage('errors', $e->getMessage());
            return $response->withRedirect($this->router->pathFor('admin/challenges'));
        }

        return $response->withRedirect($this->router->pathFor('admin/challenges'));
    });

    $app->get('/challenge/{id}', function (Request $request, Response $response, array $args) {
        $challenge = getChallenge($this->db, $args['id']);
        $categories = $this->db->select('categories', '*');
        return $this->view->render($response, 'admin/challenge.html', ['challenge' => $challenge, 'categories' => $categories]);
    })->setName('admin/challenge');

    $app->post('/challenge/{id}', function (Request $request, Response $response, array $args) {
        $postParams = $request->getParsedBody();
        if (!isset($postParams['name'])) {
            $this->flash->addMessage('errors', 'Parameter name is invalid');
            return $response->withRedirect($this->router->pathFor('admin/challenge', ['id' => $args['id']]));
        }
        if (!isset($postParams['description'])) {
            $this->flash->addMessage('errors', 'Parameter description is invalid');
            return $response->withRedirect($this->router->pathFor('admin/challenge', ['id' => $args['id']]));
        }
        if (!isset($postParams['flag'])) {
            $this->flash->addMessage('errors', 'Parameter flag is invalid');
            return $response->withRedirect($this->router->pathFor('admin/challenge', ['id' => $args['id']]));
        }
        if (!isset($postParams['point']) || !preg_match('/^[0-9]+$/', $postParams['point'])) {
            $this->flash->addMessage('errors', 'Parameter point is invalid');
            return $response->withRedirect($this->router->pathFor('admin/challenge', ['id' => $args['id']]));
        }
        if (!isset($postParams['category']) || !$this->db->has('categories', ['id' => $postParams['category']])) {
            $this->flash->addMessage('errors', 'Parameter category is invalid');
            return $response->withRedirect($this->router->pathFor('admin/challenge', ['id' => $args['id']]));
        }

        try {
            $this->db->update('challenges', [
                'name' => $postParams['name'],
                'description' => $postParams['description'],
                'flag' => $postParams['flag'],
                'point' => $postParams['point'],
                'c_id' => $postParams['category'],
                'is_open' => isset($postParams['is_open']) ? 1 : 0,
            ], ['id' => $args['id']]);
        } catch (PDOException $e) {
            $this->flash->addMessage('errors', $e->getMessage());
            return $response->withRedirect($this->router->pathFor('admin/challenge', ['id' => $args['id']]));
        }

        return $response->withRedirect($this->router->pathFor('admin/challenge', ['id' => $args['id']]));
    });

    $app->post('/challenge/{id}/delete', function (Request $request, Response $response, array $args) {
        $this->db->delete('challenges', ['id' => $args['id']]);
        return $response->withRedirect($this->router->pathFor('admin/challenges'));
    });

    $app->get('/competition', function (Request $request, Response $response, array $args) {
        $r = $this->db->select('competition', '*')[0];
        $s = new DateTime();
        $s->setTimestamp($r['start_at']);
        $r['start_at'] = $s->format('Y-m-d') . 'T' . $s->format('H:i');
        $s->setTimestamp($r['end_at']);
        $r['end_at'] = $s->format('Y-m-d') . 'T' . $s->format('H:i');

        return $this->view->render($response, 'admin/competition.html', $r);
    })->setName('comp');

    $app->post('/competition', function (Request $request, Response $response, array $args) {
        $postParams = $request->getParsedBody();

        // check required paramter
        if (!isset($postParams['name'])) {
            $this->flash->addMessage('errors', 'Parameter name is required');
            return $response->withRedirect($this->router->pathFor('comp'));
        }
        if (!isset($postParams['start_at'])) {
            $this->flash->addMessage('errors', 'Parameter start_at is required');
            return $response->withRedirect($this->router->pathFor('comp'));
        }
        if (!isset($postParams['end_at'])) {
            $this->flash->addMessage('errors', 'Parameter end_at is required');
            return $response->withRedirect($this->router->pathFor('comp'));
        }

        try {
            $name = $postParams['name'];
            $start_at = (new DateTime($postParams['start_at']))->getTimestamp();
            $end_at = (new DateTime($postParams['end_at']))->getTimestamp();
            $enabled = isset($postParams['enabled']);

            if ($start_at >= $end_at) {
                $this->flash->addMessage('errors', 'Restriction: start_at < end_at');
                return $response->withRedirect($this->router->pathFor('comp'));
            }

            $this->db->update('competition', [
                'name' => $name,
                'start_at' => $start_at,
                'end_at' => $end_at,
                'enabled' => $enabled,
            ]);

            return $response->withRedirect($this->router->pathFor('comp'));
        } catch (Exception $e) {
            $this->flash->addMessage('errors', $e);
            return $response->withRedirect($this->router->pathFor('comp'));
        }

    });
})->add($authorization(true));
