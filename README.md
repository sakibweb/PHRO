# PHRO
### PHRO is PHP Route / Router Library
PHRO is a comprehensive PHP Route/Router library class, PHRO, that allows for defining and handling HTTP routes in PHP applications.

# Features
### Route Matching:
* The library supports defining routes for different HTTP methods (GET, POST, PUT, PATCH, DELETE) with the ability to add custom methods.
* It uses URL pattern matching, including support for URL parameters (denoted by @param), to determine which route should be invoked based on the request URL and method.

### Root URL Generation:
* The root() function dynamically generates the base URL for the application, considering whether HTTPS is enabled.

### Route Groups:
* Organize routes into groups for better organization and code readability.

### Parameter Extraction:
* Automatically extract route parameters from the URL.

### IP Information Fetching:
* The fetchIPInfo() function gathers detailed IP information (private and public) from multiple external services. It maps API responses to a standard format, including location details (latitude, longitude), ISP, city, and country information.
* If an API returns valid JSON data, it is processed and merged into the internal $params array for later use.

### User Agent Parsing:
* The userAgentInfo() function attempts to extract the browser and device information from the HTTP_USER_AGENT header using regular expressions for popular browsers such as Chrome, Firefox, Safari, Edge, Opera, and Internet Explorer.

### URL Handling:
* The library handles URL trimming and splitting based on / and supports dynamic routes using @param in the URL, allowing for flexible route definitions with parameters.

### HTTP Request Handling:
* Routes are matched against the current HTTP request method (GET, POST, etc.) and the URL pattern. If a route matches, the corresponding callback function is executed.
* The method match() does the heavy lifting by comparing the requested URL and method to defined routes, supporting dynamic segments.

### Curl for External API Requests:
* It uses curl to send HTTP requests to external IP information services with a timeout mechanism for better reliability in case of delays or failures.

### Error Handling:
* Execute a callback function when no route is matched.

### Encryption:
* Encrypt and decrypt data using a secret key.

# Usage
### Creating PHRO Instance
To create a PHRO instance and define routes:
```
PHRO::initialize('/your/default/path'); // Optional: Set a default path for routes

PHRO::key('your_secret_key'); // Set encryption key

PHRO::get('/hello', function() {
    echo "Hello, World!";
});
PHRO::post('/api/user', function() {
    // Handle POST request to /api/user
});
```

### Group Routes:
```
PHRO::group('/api', function() {
    PHRO::get('/users', function($params) {
        // Routes within this group will be prefixed with '/api'
    });
});
```

### Matching Routes
PHRO matches routes based on URL patterns and HTTP methods:
```
// Define a route with parameters
PHRO::get('/user/@id', function($params) {
    $userId = $params['id'];
    // Fetch user data based on $userId
});

// Listen for incoming requests
PHRO::listen(function() {
    echo "404 Not Found";
});
```
### Handling Custom HTTP Methods
You can define routes for custom HTTP methods using the add() method:
```
PHRO::add('OPTIONS', '/api/user', function() {
    // Handle OPTIONS request to /api/user
});
```
### Handling 404 Not Found Errors
You can define a callback function to handle 404 Not Found errors:
```
PHRO::listen(function() {
    echo "404 Not Found";
});
```
### Displaying All Routes
Get all defined routes with full link and method:
```
print_r(PHRO::routes());
```

### Decryption:
Decrypts encrypted data.
```
// Make sure set encryption key
PHRO::key('your_secret_key');

// Decrypt data
$decryptedData = PHRO::decrypt($params['encryptdata']);
```


# Documentation:
* PHRO::initialize(): Initializes the router with an optional default path.
* PHRO::key(): Sets or retrieves the encryption key.
* PHRO::root(): Returns the base URL of the application.
* PHRO::get(): Defines a route for GET requests.
* PHRO::post(): Defines a route for POST requests.
* PHRO::put(): Defines a route for PUT requests.
* PHRO::patch(): Defines a route for PATCH requests.
* PHRO::delete(): Defines a route for DELETE requests.
* PHRO::add(): Defines a route for a custom HTTP method.
* PHRO::group(): Defines a group of routes with a shared prefix.
* PHRO::routes(): Returns an array of defined routes.
* PHRO::decrypt(): Decrypts encrypted data.

# Note:
* Replace your_secret_key with a strong, unique key.

Let me know if you'd like to add more features or refine specific parts of this library!
