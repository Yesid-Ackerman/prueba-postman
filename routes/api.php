<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
Route::group([
    'middleware' => 'auth:api',
    'prefix' => 'auth'
], function ($router) {
    Route::post('/register', [AuthController::class, 'register'])->name('register')->withoutMiddleware('auth:api');
    Route::post('/login', [AuthController::class, 'login'])->name('login')->withoutMiddleware('auth:api');
    Route::post('/logout', [AuthController::class, 'logout'])->middleware('auth:api')->name('logout');
    Route::post('/refresh', [AuthController::class, 'refresh'])->middleware('auth:api')->name('refresh');
    Route::post('/me', [AuthController::class, 'me'])->middleware('auth:api')->name('me');
    Route::post('/change-password', [AuthController::class, 'changePassword'])->middleware('auth:api');
    
    Route::post('/forgot-password', [AuthController::class, 'sendResetLinkEmail'])->name('password.email');
    Route::post('/reset-password', [AuthController::class, 'reset'])->name('password.update');
});