<?php

use Illuminate\Http\Request;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});


Route::get('test', function () {
    // 没有在 User 模型中 use HasApiTokens，下面就会报错。
//    if (auth()->user()->tokenCan('update')) {
//        return "can update";
//    }
//    return "can not update";
    return "successful";
})->middleware('auth:airlock');
