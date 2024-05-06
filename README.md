# PHRO
### PHRO - PHP Route / Router Library
PHRO is a PHP library for defining and handling HTTP routes in PHP applications.

## Features
- Define routes for various HTTP methods: GET, POST, PUT, PATCH, DELETE, and custom methods.
- Match routes based on URL patterns and HTTP methods.
- Extract parameters from route URLs.
- Execute callback functions when routes are matched.
- Handle 404 Not Found errors gracefully.

## Usage
### Creating PHRO Instance
To create a PHRO instance and define routes:
```
$router = new PHRO();
$router->get('/hello', function() {
    echo "Hello, World!";
});
$router->post('/api/user', function() {
    // Handle POST request to /api/user
});
```
### Matching Routes
PHRO matches routes based on URL patterns and HTTP methods:
```
// Define a route with parameters
$router->get('/user/:id', function($params) {
    $userId = $params['id'];
    // Fetch user data based on $userId
});

// Listen for incoming requests
$router->listen(function() {
    echo "404 Not Found";
});
```
### Handling Custom HTTP Methods
You can define routes for custom HTTP methods using the add() method:
```
$router->add('OPTIONS', '/api/user', function() {
    // Handle OPTIONS request to /api/user
});
```
### Handling 404 Not Found Errors
You can define a callback function to handle 404 Not Found errors:
```
$router->listen(function() {
    echo "404 Not Found";
});
```
