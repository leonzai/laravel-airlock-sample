# Laravel Airlock Sample

[https://qianjinyike.com/laravel-airlock/](https://qianjinyike.com/laravel-airlock/)

中文在下方。

## Clone

```bash
git clone https://github.com/leonzai/laravel-airlock-sample.git
```

## API Token Authentication

```bash
git checkout airlock-for-api-token
composer install
# Configure your database in the .env file.
php artisan migrate
php artisan serve
```

## SPA Authentication

#### same domain

```php
git checkout airlock-for-spa-same-domain
composer install
cp .env.example .env
# Configure your database in the .env file.
# Add "AIRLOCK_STATEFUL_DOMAINS=127.0.0.1:8000" to .env.
# You must change the domain to yours'.
php artisan migrate
php artisan key:generate
php artisan serve
```

To test: [http://127.0.0.1:8000/AirlockTest.html](http://127.0.0.1:8000/AirlockTest.html). View the console in your browser.

#### sub domain

In this case, laravel develops APIs, and the front end is SPA, and they have the same second-level domain name.

```php
git checkout airlock-for-spa-sub-domain
composer install
cp .env.example .env
# Configure your database in the .env file.
# Add "AIRLOCK_STATEFUL_DOMAINS=spa.test,m.spa.test" to .env.
# Add "SESSION_DOMAIN=.spa.test" to .env. 
# You must change the domains to yours'.
php artisan migrate
php artisan key:generate
# Configure two virtual hosts: spa.test, m.spa.test.They point to the same project which we just cloned. 
```

To test: [http://spa.test/spa.html](http://spa.test/spa.html). View the console in your browser.

# Detail

## Initialize The Project With Airlock

```php
# Install Airlock：
composer require laravel/airlock
    
# Generate configuration files and database migration files：
php artisan vendor:publish --provider="Laravel\Airlock\AirlockServiceProvider"
    
# Set length of default string type in Laravel database migration in AppServiceProvider：
\Schema::defaultStringLength(191);
    
# Configure your database in the .env file and migrate it.
php artisan migrate
```

**Set all the response to json format.**

create `app\Http\Requests\BaseRequest.php`

```php
<?php

namespace App\Http\Requests;

use Illuminate\Http\Request;

class BaseRequest extends Request
{

    public function expectsJson()
    {
        return true;
    }

    public function wantsJson()
    {
        return true;
    }
}

```

```php
# index.php
$response = $kernel->handle(
    $request = \App\Http\Requests\BaseRequest::capture()   # This line is replaced
);
```

**Add methods to the User model to manipulate tokens.**

**We do not need this in SPA authentication if we never use any method with token.**

```php
use Laravel\Airlock\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, Notifiable; 
}
```

## API token

```php
# routes/api.php

Route::post('auth/register', 'Auth\ApiController@register');
Route::post('auth/login', 'Auth\ApiController@login');
Route::post('auth/logout', 'Auth\ApiController@logout')->middleware('auth:airlock');
Route::post('auth/revoke/all/tokens', 'Auth\ApiController@revoke_all_tokens')->middleware('auth:airlock');
```

```php
# app/Http/Controllers/Auth/ApiController.php

<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\User;
use \Validator;
use Illuminate\Http\Request;

class ApiController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:airlock')->except('login', 'register');
    }

    protected function username()
    {
        return 'email';
    }

    public function register(Request $request)
    {
        $data = $this->validator($request->all())->validate();

        $user = $this->create($data);

        return $this->issue_token($user);
    }

    protected function validator(array $data)
    {
        return Validator::make($data, [
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users',],
            'name' => ['required', 'string', 'max:255', 'unique:users',],
            'password' => ['required', 'string', 'min:8', 'confirmed',],
        ]);
    }

    protected function create(array $data)
    {
        return User::forceCreate([
            'email' => $data['email'],
            'name' => $data['name'],
            'password' => password_hash($data['password'], PASSWORD_DEFAULT),
        ]);
    }

    public function logout()
    {
        auth()->user()->currentAccessToken()->delete();

        return ['message' => __('auth.sign_out_successfully')];
    }

    public function revoke_all_tokens()
    {
        if (!auth()->user()->tokenCan('*')) {
            abort(403, __('auth.forbidden'));
        }
        auth()->user()->tokens()->delete();

        return ['message' => __('auth.sign_out_successfully')];
    }

    public function login()
    {
        $user = User::where($this->username(), request($this->username()))
            ->firstOrFail();

        if (!password_verify(request('password'), $user->password)) {
            abort(403, __('auth.failed'));
        }

        return $this->issue_token($user);
    }

    /**
     * @param $user
     * @return array
     */
    protected function issue_token($user): array
    {
        return [
            'access_token' => $user->createToken('general user', ['general_user'])->plainTextToken
        ];
    }

}
```

#### Usage

```php
return $user->createToken('token-name', ['server:update'])->plainTextToken;
```

```php
if ($user->tokenCan('server:update')) {
    //
}
```

## SPA Authentication

#### Laravel develops APIs, and SPA front end are under the same domain name. 

```php
use Laravel\Airlock\Http\Middleware\EnsureFrontendRequestsAreStateful;

'api' => [
    EnsureFrontendRequestsAreStateful::class,
    'throttle:60,1',
    \Illuminate\Routing\Middleware\SubstituteBindings::class,
],
```

```php
# .env
AIRLOCK_STATEFUL_DOMAINS=your.domain
```

```
The current version of the spa authentication does not involve token scope functionality. If HasApiTokens is used in the User model, the logged-in user will have a super token scope. If there is no use HasApiTokens, an error will be reported when encountering a block of code that involves a token manipulation.
```

#### Laravel develops APIs, and SPA front end are under the same second-level domain name.


```php
composer require fruitcake/laravel-cors
php artisan vendor:publish --tag="cors"
```

```php
# config/cors.php

'paths' => ['path_your_want_to_cors', 'api/*'],
'supports_credentials' => true,
```

```php
# app/Http/Kernel.php

protected $middleware = [
    // ...
    \Fruitcake\Cors\HandleCors::class,
];
```

```php
# .env

AIRLOCK_STATEFUL_DOMAINS=spa.test,api.spa.test

SESSION_DOMAIN=.spa.test
```

```php
use Laravel\Airlock\Http\Middleware\EnsureFrontendRequestsAreStateful;

'api' => [
    EnsureFrontendRequestsAreStateful::class,
    'throttle:60,1',
    \Illuminate\Routing\Middleware\SubstituteBindings::class,
],
```

```php
// spa 页面 

axios.defaults.withCredentials = true;
```

To authenticate your SPA, your SPA's login page should first make a request to the `/airlock/csrf-cookie` route to initialize CSRF protection for the application:

    axios.get('/airlock/csrf-cookie');



# Laravel Airlock 例子

## 克隆

```bash
git clone https://github.com/leonzai/laravel-airlock-sample.git
```

## API Token 认证

```bash
git checkout airlock-for-api-token
composer install
# Configure your database in the .env file.
php artisan migrate
php artisan serve
```

## SPA 认证

#### same domain

```php
git checkout airlock-for-spa-same-domain
composer install
cp .env.example .env
# Configure your database in the .env file.
# Add "AIRLOCK_STATEFUL_DOMAINS=127.0.0.1:8000" to .env.
# You must change the domain to yours'.
php artisan migrate
php artisan key:generate
php artisan serve
```

测试地址: [http://127.0.0.1:8000/AirlockTest.html](http://127.0.0.1:8000/AirlockTest.html)。 测试时候请查看浏览器的控制台。

#### sub domain

在这种情况下，laravel开发API，前端是SPA，并且它们具有相同的二级域名。

```php
git checkout airlock-for-spa-sub-domain
composer install
cp .env.example .env
# Configure your database in the .env file.
# Add "AIRLOCK_STATEFUL_DOMAINS=spa.test,m.spa.test" to .env.
# Add "SESSION_DOMAIN=.spa.test" to .env. 
# You must change the domains to yours'.
php artisan migrate
php artisan key:generate
# Configure two virtual hosts: spa.test, m.spa.test.They point to the same project which we just cloned. 
```

测试地址: [http://spa.test/spa.html](http://spa.test/spa.html). 测试时候请查看浏览器的控制台。

# 细节

## 初始化项目和 Airlock

```php
# 安装 Airlock：
composer require laravel/airlock
    
# 生成配置文件和数据库迁移文件：
php artisan vendor:publish --provider="Laravel\Airlock\AirlockServiceProvider"
    
# 在 AppServiceProvider 中设置 Laravel 数据库迁移中的默认字符串类型的长度：
\Schema::defaultStringLength(191);
    
# 配置数据库并进行数据库迁移
php artisan migrate
```

**设置所有请求后的相应数据为 json 格式**

新建 `app\Http\Requests\BaseRequest.php`

```php
<?php

namespace App\Http\Requests;

use Illuminate\Http\Request;

class BaseRequest extends Request
{

    public function expectsJson()
    {
        return true;
    }

    public function wantsJson()
    {
        return true;
    }
}

```

```php
# index.php
$response = $kernel->handle(
    $request = \App\Http\Requests\BaseRequest::capture()   # This line is replaced
);
```

**给 User 模型添加用来操作 token 的方法**

**如果我们不使用任何带有令牌的方法，则在 SPA 身份验证中不需要下面的配置。**

```php
use Laravel\Airlock\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, Notifiable; 
}
```

## API token

```php
# routes/api.php

Route::post('auth/register', 'Auth\ApiController@register');
Route::post('auth/login', 'Auth\ApiController@login');
Route::post('auth/logout', 'Auth\ApiController@logout')->middleware('auth:airlock');
Route::post('auth/revoke/all/tokens', 'Auth\ApiController@revoke_all_tokens')->middleware('auth:airlock');
```

```php
# app/Http/Controllers/Auth/ApiController.php

<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\User;
use \Validator;
use Illuminate\Http\Request;

class ApiController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:airlock')->except('login', 'register');
    }

    protected function username()
    {
        return 'email';
    }

    public function register(Request $request)
    {
        $data = $this->validator($request->all())->validate();

        $user = $this->create($data);

        return $this->issue_token($user);
    }

    protected function validator(array $data)
    {
        return Validator::make($data, [
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users',],
            'name' => ['required', 'string', 'max:255', 'unique:users',],
            'password' => ['required', 'string', 'min:8', 'confirmed',],
        ]);
    }

    protected function create(array $data)
    {
        return User::forceCreate([
            'email' => $data['email'],
            'name' => $data['name'],
            'password' => password_hash($data['password'], PASSWORD_DEFAULT),
        ]);
    }

    public function logout()
    {
        auth()->user()->currentAccessToken()->delete();

        return ['message' => __('auth.sign_out_successfully')];
    }

    public function revoke_all_tokens()
    {
        if (!auth()->user()->tokenCan('*')) {
            abort(403, __('auth.forbidden'));
        }
        auth()->user()->tokens()->delete();

        return ['message' => __('auth.sign_out_successfully')];
    }

    public function login()
    {
        $user = User::where($this->username(), request($this->username()))
            ->firstOrFail();

        if (!password_verify(request('password'), $user->password)) {
            abort(403, __('auth.failed'));
        }

        return $this->issue_token($user);
    }

    /**
     * @param $user
     * @return array
     */
    protected function issue_token($user): array
    {
        return [
            'access_token' => $user->createToken('general user', ['general_user'])->plainTextToken
        ];
    }

}
```

#### 用法

```php
return $user->createToken('token-name', ['server:update'])->plainTextToken;
```

```php
if ($user->tokenCan('server:update')) {
    //
}
```

## SPA 认证

#### Laravel API，SPA 前端使用相同的域名。 

```php
use Laravel\Airlock\Http\Middleware\EnsureFrontendRequestsAreStateful;

'api' => [
    EnsureFrontendRequestsAreStateful::class,
    'throttle:60,1',
    \Illuminate\Routing\Middleware\SubstituteBindings::class,
],
```

```php
# .env
AIRLOCK_STATEFUL_DOMAINS=your.domain
```

```
SPA 认证方式目前的版本不涉及 token 范围功能。如果在 User 模型中 use HasApiTokens，那么登录的用户就会拥有超级 token 范围。如果没有 use HasApiTokens，在碰到涉及到 token 范围的代码块就会报错。
```

#### Laravel API，SPA 前端使用相同的二级域名。


```php
composer require fruitcake/laravel-cors
php artisan vendor:publish --tag="cors"
```

```php
# config/cors.php

'paths' => ['path_your_want_to_cors', 'api/*'],
'supports_credentials' => true,
```

```php
# app/Http/Kernel.php

protected $middleware = [
    // ...
    \Fruitcake\Cors\HandleCors::class,
];
```

```php
# .env

AIRLOCK_STATEFUL_DOMAINS=spa.test,api.spa.test

SESSION_DOMAIN=.spa.test
```

```php
use Laravel\Airlock\Http\Middleware\EnsureFrontendRequestsAreStateful;

'api' => [
    EnsureFrontendRequestsAreStateful::class,
    'throttle:60,1',
    \Illuminate\Routing\Middleware\SubstituteBindings::class,
],
```

```php
// spa 页面 

axios.defaults.withCredentials = true;
```

要验证您的 SPA，您的 SPA 的登录页面应首先向 /airlock/csrf-cookie 路由发出请求，以初始化该应用程序的CSRF保护：

    axios.get('/airlock/csrf-cookie');
