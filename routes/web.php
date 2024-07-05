<?php

use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});
Route::get('/test-email', function () {
    $details = [
        'title' => 'Test Email',
        'body' => 'This is a test email sent from Laravel'
    ];

    Mail::to('Ackerman17_21@hotmail.com')->send(new \App\Mail\TestEmail($details));

    return 'Email sent!';
});