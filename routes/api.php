<?php

Route::post('auth/register', 'Auth\ApiController@register');
Route::post('auth/login', 'Auth\ApiController@login');
Route::post('auth/logout', 'Auth\ApiController@logout')->middleware('auth:airlock');
Route::post('auth/revoke/all/tokens', 'Auth\ApiController@revoke_all_tokens')->middleware('auth:airlock');

