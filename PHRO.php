<?php
/**
 * PHRO is PHP Route / Router Library
 * A PHP library for defining and handling HTTP routes in PHP applications.
 */
class PHRO {

    /**
     * Array to store server URL segments.
     * @var array
     */
    private static $server_url = [];

    /**
     * HTTP request method.
     * @var string
     */
    private static $server_method;

    /**
     * Callback function to execute when a route is matched.
     * @var callable
     */
    private static $callback;

    /**
     * Flag indicating whether a route has been matched.
     * @var bool
     */
    private static $matched = false;

    /**
     * Array to store URL parameters.
     * @var array
     */
    private static $params = [];

    /**
     * Regular expression pattern to trim URL segments.
     * @var string
     */
    private static $trim = '/\^$/';

    /**
     * Default home URL for routes.
     * @var string
     */
    private static $default_home_url;

    /**
     * Initializes the PHRO object with default home URL.
     *
     * @param string $default_home_url Default home URL for routes.
     * @return void
     */
    public static function initialize($default_home_url = ''){
        self::$default_home_url = $default_home_url;
        $url = trim($_SERVER['REQUEST_URI'], self::$trim);
        self::$server_method = strtolower($_SERVER['REQUEST_METHOD']);
        self::$server_url = explode('/', $url);
    }

    /**
     * Get the root URL for the application.
     *
     * @return string The base URL.
     */
    public static function root(){
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
        $domain = $_SERVER['HTTP_HOST'];
        return rtrim($protocol . $domain . self::$default_home_url, '/');
    }

    /**
     * Define a route for GET method.
     *
     * @param string $url Route URL pattern.
     * @param callable $callback Callback function to execute when route is matched.
     * @return void
     */
    public static function get($url, $callback){
        self::match('get', $url, $callback);
    }

    /**
     * Define a route for POST method.
     *
     * @param string $url Route URL pattern.
     * @param callable $callback Callback function to execute when route is matched.
     * @return void
     */
    public static function post($url, $callback){
        self::match('post', $url, $callback);
    }

    /**
     * Define a route for PUT method.
     *
     * @param string $url Route URL pattern.
     * @param callable $callback Callback function to execute when route is matched.
     * @return void
     */
    public static function put($url, $callback){
        self::match('put', $url, $callback);
    }

    /**
     * Define a route for PATCH method.
     *
     * @param string $url Route URL pattern.
     * @param callable $callback Callback function to execute when route is matched.
     * @return void
     */
    public static function patch($url, $callback){
        self::match('patch', $url, $callback);
    }

    /**
     * Define a route for DELETE method.
     *
     * @param string $url Route URL pattern.
     * @param callable $callback Callback function to execute when route is matched.
     * @return void
     */
    public static function delete($url, $callback){
        self::match('delete', $url, $callback);
    }

    /**
     * Define a route for custom HTTP method.
     *
     * @param string $method Custom HTTP method.
     * @param string $url Route URL pattern.
     * @param callable $callback Callback function to execute when route is matched.
     * @return void
     */
    public static function add($method, $url, $callback){
        self::match(strtolower($method), $url, $callback);
    }

    /**
     * Match the route URL pattern with the current request URL.
     *
     * @param string $method HTTP method.
     * @param string $url Route URL pattern.
     * @param callable $callback Callback function to execute when route is matched.
     * @return void
     */
    private static function match($method, $url, $callback){
        if(self::$matched){
            return;
        }
        
        $url = trim(self::$default_home_url.$url, self::$trim);
        $current_url = explode('/', $url);
        $url_length = count($current_url);

        if($method != self::$server_method){
            return;
        }
        if($url_length != count(self::$server_url)){
            return;
        }
        
        $matched = true;

        for($i = 0; $i < $url_length; $i++){
            if($current_url[$i] == self::$server_url[$i]){
                continue;
            }
            if(isset($current_url[$i][0]) && $current_url[$i][0] == '@'){
                self::$params[substr($current_url[$i], 1)] = self::$server_url[$i];
                continue;
            }
            $matched = false;
            break;
        }

        if($matched){
            self::$callback = $callback;
            self::$matched = true;
        }
    }

    /**
     * Fetch IP information from multiple sources with fallbacks.
     *
     * @return array
     */
    public static function fetchIPInfo() {
        $urls = [
            "http://ip-api.com/json/",
            "https://ipinfo.io/json/",
            "https://freegeoip.app/json/",
            "https://api.ipbase.com/v1/json/",
            "http://ip-api.com/json/?fields=status,message,country,countryCode,region,regionName,city,lat,lon,zip,timezone,isp,org,as,mobile,proxy,query",
            "https://api.ipify.org/?format=json"
        ];
        
        $timeout = 0.8;
        
        foreach ($urls as $url) {
            try {
                $response = self::getHTTPResponse($url, $timeout);
                $data = json_decode($response, true);
                if (json_last_error() === JSON_ERROR_NONE && isset($data['status']) && $data['status'] === 'success') {
                    self::$params = array_merge(self::$params, $data);
                    return $data;
                }
            } catch (Exception $e) {
            }
        }
        return [];
    }

    /**
     * Perform an HTTP GET request with a specified timeout.
     *
     * @param string $url The URL to fetch data from.
     * @param int $timeout The timeout duration in seconds.
     * @return string The response body.
     * @throws Exception If the request fails or times out.
     */
    private static function getHTTPResponse($url, $timeout) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
        $response = curl_exec($ch);

        if (curl_errno($ch)) {
            curl_close($ch);
            throw new Exception('Curl error: ' . curl_error($ch));
        }

        curl_close($ch);
        return $response;
    }

    /**
     * Listen for incoming HTTP requests and execute matching route callback.
     *
     * @param callable|null $not_found_callback Callback function to execute when no route is matched.
     * @return void
     */
    public static function listen($not_found_callback = null){
        if(!self::$matched){
            if ($not_found_callback !== null && is_callable($not_found_callback)) {
                call_user_func($not_found_callback);
            } else {
                header("HTTP/1.1 404 Not Found");
            }
            return;
        }
        self::fetchIPInfo();
        self::$params = array_merge(self::$params, $_SERVER, $_GET, $_POST, $_COOKIE, $_FILES, $_REQUEST);
        call_user_func(self::$callback, self::$params);
    }
}
?>
