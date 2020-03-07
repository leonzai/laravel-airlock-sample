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
