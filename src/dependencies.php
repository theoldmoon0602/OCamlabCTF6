<?php
// DIC configuration

$container = $app->getContainer();

// view renderer
$container['renderer'] = function ($c) {
    $settings = $c->get('settings')['renderer'];
    return new Slim\Views\PhpRenderer($settings['template_path']);
};

// monolog
$container['logger'] = function ($c) {
    $settings = $c->get('settings')['logger'];
    $logger = new Monolog\Logger($settings['name']);
    $logger->pushProcessor(new Monolog\Processor\UidProcessor());
    $logger->pushHandler(new Monolog\Handler\StreamHandler($settings['path'], $settings['level']));
    return $logger;
};

function baseUrl($app)
{
    if (is_string($app->uri)) {
        return $app->uri;
    }
    if (method_exists($app->uri, 'getBaseUrl')) {
        return $app->uri->getBaseUrl();
    }
}


$container['view'] = function ($container) {
  $path_to_templates = __DIR__ . '/../templates/';
  $path_to_cache = __DIR__ . '/../caches/';
  $view = new \Slim\Views\Twig($path_to_templates, [
      'cache' => false,
      'debug' => true,
      // 'cache' => $path_to_cache
  ]);
  $view->addExtension(new Knlv\Slim\Views\TwigMessages(
      new Slim\Flash\Messages()
  ));

  // Instantiate and add Slim specific extension
  $basePath = rtrim(str_ireplace('index.php', '', $container->get('request')->getUri()->getBasePath()), '/');
  $view->addExtension(new Slim\Views\TwigExtension($container->get('router'), $basePath));
  $view->addExtension(new Twig_Extension_Debug());  
  $view->getEnvironment()->addFilter(new Twig_Filter('array_column', 'array_column'));
  $view->getEnvironment()->addGlobal('session', $_SESSION);

  return $view;
};

$container['flash'] = function () {
    return new \Slim\Flash\Messages();
};

$container['db'] = function($c) {
  $settings = $c->get('settings')['db'];
  $medoo = new Medoo\Medoo($settings);
  return $medoo;
};
