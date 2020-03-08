<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\User;
use \Validator;
use Illuminate\Http\Request;

class AirlockSPAController extends Controller
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

        auth()->login($user);

        return ['message' => __('auth.sign_up_successfully')];
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
        auth('web')->logout();

        return ['message' => __('auth.sign_out_successfully')];
    }

    public function login()
    {

        $credentials = \request()->only($this->username(), 'password');

        if (auth()->attempt($credentials)) {
            return ['message' => __('auth.sign_in_successfully')];
        }

        abort(403, __('auth.failed'));

    }
}
