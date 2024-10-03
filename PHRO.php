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
     * Array to store all defined routes.
     * @var array
     */
    private static $routes = [];

    /**
     * Secret key for encription.
     * @var string
     */
    private static $key = '';

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
        preg_match('/^(.*?)\?/', $url, $matches);

        if (isset($matches[1])) {
            self::$server_url = explode('/', trim($matches[1], '/'));
        } else {
            self::$server_url = explode('/', trim($url, '/'));
        }
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
     * Define a group of routes with a shared URL prefix.
     *
     * This method allows you to define multiple routes under a specific URL prefix. 
     * The callback function provided will contain the route definitions.
     *
     * @param string $prefix The URL prefix to be added to the group of routes.
     * @param callable $callback The callback function where route definitions are made.
     * @return void
     */
    public static function group($prefix, $callback) {
        $original_prefix = self::$default_home_url;
        self::$default_home_url .= $prefix;
    
        call_user_func($callback);
    
        self::$default_home_url = $original_prefix;
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
        self::$routes[] = [
            'short' => $url,
            'method' => strtoupper($method),
            'link' => self::root() . '/' . trim($url, '/')
        ];

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
            "http://ip-api.com/json/?fields=status,message,country,countryCode,region,regionName,city,lat,lon,zip,timezone,isp,org,as,mobile,proxy,query",
            "http://ip-api.com/json/",
            "https://ipinfo.io/json/",
            "https://freegeoip.app/json/",
            "https://api.ipbase.com/v1/json/",
            "https://api.ipify.org/?format=json"
        ];

        $keys = [
            'status'       => 'none',
            'message'      => 'none',
            'ip'           => 'none',
            'hostname'     => 'none',
            'city'         => 'none',
            'region'       => 'none',
            'country'      => 'none',
            'countryCode'  => 'none',
            'loc'          => 'none',
            'latitude'     => null,
            'longitude'    => null,
            'zip'          => 'none',
            'timezone'     => 'none',
            'isp'          => 'none',
            'org'          => 'none',
            'as'           => 'none',
            'mobile'       => false,
            'proxy'        => false,
        ];
        
        $timeout = 0.8;
        
        foreach ($urls as $url) {
            try {
                $response = self::getHTTPResponse($url, $timeout);
                $data = json_decode($response, true);

                if (json_last_error() === JSON_ERROR_NONE) {
                    $mappedData = self::mapAPIDataToKeys($data);
                    foreach ($keys as $key => $default) {
                        if (isset($mappedData[$key])) {
                            $keys[$key] = $mappedData[$key];
                        }
                    }
                    self::$params = array_merge(self::$params, $mappedData);
                    return $mappedData;
                }
            } catch (Exception $e) {
            }
        }
        return [];
    }

    /**
     * Maps the API data to the expected keys format.
     *
     * @param array $data The data from the API response.
     * @return array Mapped data.
     */
    private static function mapAPIDataToKeys($data) {
        $mappedData = [];

        $ipaddress = 'UNKNOWN';
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ipList = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ipaddress = trim($ipList[0]);
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED'])) {
            $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
        } elseif (!empty($_SERVER['HTTP_FORWARDED_FOR'])) {
            $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
        } elseif (!empty($_SERVER['HTTP_FORWARDED'])) {
            $ipaddress = $_SERVER['HTTP_FORWARDED'];
            $ipaddress = $_SERVER['REMOTE_ADDR'];
        } elseif (getenv('HTTP_CLIENT_IP')) {
            $ipaddress = getenv('HTTP_CLIENT_IP');
        } elseif (getenv('HTTP_X_FORWARDED_FOR')) {
            $ipaddress = getenv('HTTP_X_FORWARDED_FOR');
        } elseif (getenv('HTTP_X_FORWARDED')) {
            $ipaddress = getenv('HTTP_X_FORWARDED');
        } elseif (getenv('HTTP_FORWARDED_FOR')) {
            $ipaddress = getenv('HTTP_FORWARDED_FOR');
        } elseif (getenv('HTTP_FORWARDED')) {
            $ipaddress = getenv('HTTP_FORWARDED');
        } elseif (getenv('REMOTE_ADDR')) {
            $ipaddress = getenv('REMOTE_ADDR');
        } else {
            $ipaddress = 'UNKNOWN';
        }
        $mappedData['private'] = $ipaddress;

        if (isset($data['query'])) {
            $mappedData['public'] = $data['query'];
        }

        if (isset($data['loc'])) {
            [$mappedData['latitude'], $mappedData['longitude']] = explode(',', $data['loc']);
        } else {
            if (isset($data['lat'])) {
                $mappedData['latitude'] = $data['lat'];
            }
            if (isset($data['lon'])) {
                $mappedData['longitude'] = $data['lon'];
            }
        }

        $keyMapping = [
            'private'     => ['private'],
            'public'     => ['query'],
            'hostname'     => ['hostname'],
            'city'         => ['city'],
            'region'       => ['region', 'regionName', 'region_name'],
            'country'      => ['country', 'country_name'],
            'countryCode'  => ['countryCode', 'country_code'],
            'zip'          => ['zip', 'zip_code', 'postal'],
            'timezone'     => ['timezone', 'time_zone'],
            'isp'          => ['isp'],
            'org'          => ['org'],
            'as'           => ['as'],
            'mobile'       => ['mobile'],
            'proxy'        => ['proxy'],
        ];

        foreach ($keyMapping as $mappedKey => $apiKeys) {
            foreach ($apiKeys as $apiKey) {
                if (isset($data[$apiKey])) {
                    $mappedData[$mappedKey] = $data[$apiKey];
                    break;
                }
            }
        }

        return $mappedData;
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
     * Extract comprehensive information from the HTTP_USER_AGENT string and store it in $params.
     *
     * @return void
     */
    public static function userAgentInfo() {
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        $browsers = [
            'Chrome' => '/Chrome\/([0-9.]+)/',
            'Firefox' => '/Firefox\/([0-9.]+)/',
            'Safari' => '/Safari\/([0-9.]+)(?!.*Chrome)/',
            'Edge' => '/Edge\/([0-9.]+)/',
            'Opera' => '/OPR\/([0-9.]+)/',
            'IE' => '/MSIE ([0-9.]+);|Trident\/.*rv:([0-9.]+)/',
            'Brave' => '/Brave\/([0-9.]+)/',
            'PlayStation' => '/PlayStation 4|PlayStation Vita/',
            'SamsungBrowser' => '/SamsungBrowser\/([0-9.]+)/',
            'Xbox' => '/Xbox|Xbox Series X/',
            'PlayStation' => '/PlayStation 4|PlayStation Vita/',
        ];

        $platforms = [
            'Windows' => '/Windows NT ([0-9.]+)/',
            'Mac' => '/Mac OS X ([0-9._]+)/',
            'Linux' => '/Linux/',
            'iPhone' => '/iPhone; CPU iPhone OS ([0-9_]+)/',
            'iPad' => '/iPad; CPU OS ([0-9_]+)/',
            'Android' => '/Android ([0-9.]+)/',
            'Xbox' => '/Xbox; Windows NT ([0-9.]+)/',
            'PlayStation' => '/PlayStation 4|PlayStation Vita/',
            'Chrome OS' => '/CrOS ([a-zA-Z0-9.]+)/',
            'Nvidia Shield' => '/SHIELD Tablet K1/',
        ];

        $devices = [
            'Samsung' => '/SM-([A-Za-z0-9]+)/',
            'Nvidia Shield' => '/SHIELD Tablet K1/',
            'iPhone' => '/iPhone/',
            'iPad' => '/iPad/',
            'Android' => '/Android/',
            'Xbox' => '/Xbox/',
            'PlayStation' => '/PlayStation/',
            'Google Pixel' => '/Pixel [0-9]+/',
            'OnePlus' => '/ONEPLUS/',
            'Huawei' => '/Huawei|HUAWEI/',
            'Xiaomi' => '/Mi|Redmi/',
        ];

        $bots = [
            'GoogleBot' => '/Googlebot/',
            'YandexBot' => '/YandexBot/',
            'DiscordBot' => '/Discordbot/',
            'TwitterBot' => '/Twitterbot/',
            'DuckDuckGoBot' => '/DuckDuckBot/',
            'BaiduBot' => '/Baiduspider/',
        ];

        foreach ($browsers as $browser => $regex) {
            if (preg_match($regex, $user_agent, $matches)) {
                self::$params['browser'] = $browser;
                self::$params['browser_version'] = $matches[1] ?? 'unknown';
                break;
            }
        }

        foreach ($platforms as $platform => $regex) {
            if (preg_match($regex, $user_agent, $matches)) {
                self::$params['platform'] = $platform;
                self::$params['platform_version'] = str_replace('_', '.', $matches[1] ?? 'unknown');
                break;
            }
        }

        foreach ($devices as $device => $regex) {
            if (preg_match($regex, $user_agent)) {
                self::$params['device'] = $device;
                break;
            }
        }

        foreach ($bots as $bot => $regex) {
            if (preg_match($regex, $user_agent)) {
                self::$params['bot'] = $bot;
                break;
            }
        }

        self::$params['browser'] = self::$params['browser'] ?? 'unknown';
        self::$params['browser_version'] = self::$params['browser_version'] ?? 'unknown';
        self::$params['platform'] = self::$params['platform'] ?? 'unknown';
        self::$params['platform_version'] = self::$params['platform_version'] ?? 'unknown';
        self::$params['device'] = self::$params['device'] ?? 'unknown';
        self::$params['bot'] = self::$params['bot'] ?? 'no';
        self::$params['is_mobile'] = preg_match('/Mobile|Android|iPhone|iPad/', $user_agent) ? true : false;
        self::$params['is_desktop'] = !self::$params['is_mobile'];
    }

    /**
     * Get all defined routes with full link and method.
     *
     * @return array All routes with link and method.
     */
    public static function routes() {
        return self::$routes;
    }

    /**
     * Create an unchangeable network identity key
     *
     * This function generates a strong, unique identity key based on
     * user network-related data. The key will remain consistent as long
     * as the key data remains unchanged.
     *
     * @param array $data Network information and headers
     * @return string Unchangeable identity key (hash)
     */
    public static function netKey($data) {
        try {
            $identityKeys = [
                'private', 'public', 'latitude', 'longitude', 'city', 'country', 'timezone',
                'proxy', 'isp', 'zip', 'HTTP_HOST', 'SERVER_NAME', 'SERVER_ADDR', 'REMOTE_ADDR'
            ];

            $identityData = [];
            foreach ($identityKeys as $key) {
                $identityData[$key] = $data[$key] ?? '';
            }

            $identityString = json_encode($identityData);

            $secretKey = self::$key;
            if (empty($secretKey) || strlen($secretKey) < 18) {
                throw new Exception('New key must be at least 18 characters long.');
            }
            
            $identityKey = hash_hmac('sha512', $identityString, $secretKey);

            return $identityKey;
        } catch (Exception $e) {
            return 'Error generating network key: ' . $e->getMessage();
        }
    }

    /**
     * Create an unchangeable device identity key
     *
     * This function generates a strong, unique identity key based on
     * user device-related data. The key will remain consistent as long
     * as the key data remains unchanged.
     *
     * @param array $data Device information and headers
     * @return string Unchangeable identity key (hash)
     */
    public static function deviceKey($data) {
        try {
            $identityKeys = [
                'is_mobile', 'is_desktop', 'browser', 'browser_version', 'platform', 'platform_version',
                'device', 'HTTP_USER_AGENT', 'HTTP_ACCEPT_LANGUAGE', 'SERVER_SIGNATURE', 'SERVER_SOFTWARE'
            ];

            $identityData = [];
            foreach ($identityKeys as $key) {
                $identityData[$key] = $data[$key] ?? '';
            }

            $identityString = json_encode($identityData);

            $secretKey = self::$key;
            if (empty($secretKey) || strlen($secretKey) < 18) {
                throw new Exception('New key must be at least 18 characters long.');
            }
            
            $deviceKey = hash_hmac('sha512', $identityString, $secretKey);

            return $deviceKey;
        } catch (Exception $e) {
            return 'Error generating device key: ' . $e->getMessage();
        }
    }

    /**
     * Encrypt the data array
     *
     * @param array $data The data to encrypt
     * @return string|null Encrypted data (base64url encoded) or null on failure
     */
    private static function encrypt($data) {
        try {
            $secretKey = self::$key;
            if (empty($secretKey) || strlen($secretKey) < 18) {
                throw new Exception('New key must be at least 18 characters long.');
            }

            $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-gcm'));

            $encryptedData = openssl_encrypt(
                json_encode($data),
                'aes-256-gcm',
                $secretKey,
                0,
                $iv,
                $tag
            );

            $output = $iv . $tag . $encryptedData;
            return rtrim(strtr(base64_encode($output), '+/', '-_'), '=');
        } catch (Exception $e) {
            return null;
        }
    }

    /**
     * Decrypt the encrypted data
     *
     * @param string $encryptedData The base64url encoded encrypted data
     * @return array|null Decrypted data or null on failure
     */
    public static function decrypt($encryptedData) {
        try {
            $secretKey = self::$key;
            if (empty($secretKey) || strlen($secretKey) < 18) {
                throw new Exception('New key must be at least 18 characters long.');
            }

            $decodedData = base64_decode(strtr($encryptedData, '-_', '+/'));
            
            $ivLength = openssl_cipher_iv_length('aes-256-gcm');
            $tagLength = 16;
            $iv = substr($decodedData, 0, $ivLength);
            $tag = substr($decodedData, $ivLength, $tagLength);
            $encryptedPayload = substr($decodedData, $ivLength + $tagLength);

            $decryptedData = openssl_decrypt($encryptedPayload, 'aes-256-gcm', $secretKey, 0, $iv, $tag);

            if ($decryptedData === false) {
                return null;
            }

            return json_decode($decryptedData, true);
        } catch (Exception $e) {
            return null;
        }
    }

    /**
     * Updates the default encryption key.
     *
     * @param string $new_key The new encryption key.
     * @return array
     */
    public static function key($new_key) {
        try {
            if (!empty($new_key) && strlen($new_key) >= 18) {
                self::$key = $new_key;
                return ['status' => true, 'message' => 'Key updated successfully.', 'data' => null];
            } else {
                throw new Exception('New key must be at least 18 characters long.');
            }
        } catch (Exception $e) {
            return ['status' => false, 'message' => $e->getMessage(), 'data' => null];
        }
    }

    /**
     * Collect and process request data, generate unique identifiers, and handle encryption.
     * 
     * The `footprint` function is used to capture various request information and generate unique keys
     * for network and device identification. This function performs the following actions:
     * 
     * - Fetches IP and user-agent information.
     * - Collects raw input data from the HTTP request body.
     * - Merges various PHP superglobals (e.g., $_SERVER, $_GET, $_POST, $_COOKIE, $_FILES, $_REQUEST) and custom data.
     * - Generates unique keys (`netKey` and `devicekey`) based on request parameters.
     * - Encrypts the collected data and includes it in the final request parameters.
     * 
     * The merged data is returned as `self::$params`.
     *
     * @return array Updated and enriched request parameters.
     */
    public static function footprint(){
        self::fetchIPInfo();
        self::userAgentInfo();
        $rawBody = ['raw_body' => file_get_contents('php://input')];
        $times = ['request_timestamp' => time(), 'request_time' => date("h:i A"), 'request_date' => date("d/m/y")];
        self::$params = array_merge(self::$params, $times, $_SERVER, $_GET, $_POST, $_COOKIE, $_FILES, $_REQUEST, $rawBody, getallheaders());
        $netKey = array( "netkey" => self::netKey(self::$params) );
        $devicekey = array( "devicekey" => self::devicekey(self::$params) );
        self::$params = array_merge(self::$params, $netKey, $devicekey);
        $encryptData = array( "encryptdata" => self::encrypt(self::$params) );
        self::$params = array_merge(self::$params, $encryptData);
        return self::$params;
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
        call_user_func(self::$callback, self::footprint());
    }
}
?>
