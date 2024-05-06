<?php
/**
 * PHRO is PHP Route / Router Library
 * @author Sakibur Rahman (@sakibweb)
 * 
 * A PHP library for defining and handling HTTP routes in PHP applications.
 */
class PHRO {

    /**
     * Array to store server URL segments.
     * @var array
     */
    private $server_url = [];

    /**
     * HTTP request method.
     * @var string
     */
    private $server_method;

    /**
     * Callback function to execute when a route is matched.
     * @var callable
     */
    private $callback;

    /**
     * Flag indicating whether a route has been matched.
     * @var bool
     */
    private $matched = false;

    /**
     * Array to store URL parameters.
     * @var array
     */
    private $params = [];

    /**
     * Regular expression pattern to trim URL segments.
     * @var string
     */
    private $trim = '/\^$/';

    /**
     * Default home URL for routes.
     * @var string
     */
    private $default_home_url;

    /**
     * Constructor function.
     * Initializes the PHRO object with default home URL.
     *
     * @param string $default_home_url Default home URL for routes.
     * @return void
     */
    function __construct($default_home_url = ''){
        $this->default_home_url = $default_home_url;
        $url = trim($_SERVER['REQUEST_URI'], $this->trim);
        $this->server_method = strtolower($_SERVER['REQUEST_METHOD']);
        $this->server_url = explode('/', $url);
    }

    /**
     * Define a route for GET method.
     *
     * @param string $url Route URL pattern.
     * @param callable $callback Callback function to execute when route is matched.
     * @return void
     */
    public function get($url, $callback){
        $this->match('get', $url, $callback);
    }

    /**
     * Define a route for POST method.
     *
     * @param string $url Route URL pattern.
     * @param callable $callback Callback function to execute when route is matched.
     * @return void
     */
    public function post($url, $callback){
        $this->match('post', $url, $callback);
    }

    /**
     * Define a route for PUT method.
     *
     * @param string $url Route URL pattern.
     * @param callable $callback Callback function to execute when route is matched.
     * @return void
     */
    public function put($url, $callback){
        $this->match('put', $url, $callback);
    }

    /**
     * Define a route for PATCH method.
     *
     * @param string $url Route URL pattern.
     * @param callable $callback Callback function to execute when route is matched.
     * @return void
     */
    public function patch($url, $callback){
        $this->match('patch', $url, $callback);
    }

    /**
     * Define a route for DELETE method.
     *
     * @param string $url Route URL pattern.
     * @param callable $callback Callback function to execute when route is matched.
     * @return void
     */
    public function delete($url, $callback){
        $this->match('delete', $url, $callback);
    }

    /**
     * Define a route for custom HTTP method.
     *
     * @param string $method Custom HTTP method.
     * @param string $url Route URL pattern.
     * @param callable $callback Callback function to execute when route is matched.
     * @return void
     */
    public function add($method, $url, $callback){
        $this->match(strtolower($method), $url, $callback);
    }

    /**
     * Match the route URL pattern with the current request URL.
     *
     * @param string $method HTTP method.
     * @param string $url Route URL pattern.
     * @param callable $callback Callback function to execute when route is matched.
     * @return void
     */
    private function match($method, $url, $callback){
        if($this->matched){
            return;
        }
        
        $url = trim($this->default_home_url.$url, $this->trim);
        $current_url = explode('/', $url);
        $url_length = count($current_url);

        if($method != $this->server_method){
            return;
        }
        if($url_length != count($this->server_url)){
            return;
        }

        $matched = true;

        for($i = 0; $i < $url_length; $i++){
            if($current_url[$i] == $this->server_url[$i]){
                continue;
            }
            if(isset($current_url[$i][0]) && $current_url[$i][0] == ':'){
                $this->params[substr($current_url[$i], 1)] = $this->server_url[$i];
                continue;
            }
            $matched = false;
            break;
        }

        if($matched){
            $this->callback = $callback;
            $this->matched = true;
        }
    }

    /**
     * Listen for incoming HTTP requests and execute matching route callback.
     *
     * @param callable|null $not_found_callback Callback function to execute when no route is matched.
     * @return void
     */
    public function listen($not_found_callback = null){
        if(!$this->matched){
            if ($not_found_callback !== null && is_callable($not_found_callback)) {
                call_user_func($not_found_callback);
            } else {
                header("HTTP/1.1 404 Not Found");
            }
            return;
        }
        call_user_func($this->callback, $this->params);
    }
}
?>
