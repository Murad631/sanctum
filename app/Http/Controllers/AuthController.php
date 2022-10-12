<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $fields = Validator::make($request->all(), [
            'name' => 'required|string',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string|confirmed'
        ]);
        if ($fields->fails()) {
            return response([
                'message' => $fields->errors(),
            ], Response::HTTP_UNAUTHORIZED);
        }
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password)
        ]);

        $token = $user->createToken('ims_token')->plainTextToken;

        $cookie = cookie('jwt', $token, 60 * 24); // 1 Day.
        return response([
            'message' => 'success',
            'user' => $user,
            'token' => $token
        ])->withCookie($cookie);
    }

    public function login(Request $request)
    {
        $fields = $request->validate([
            'email' => 'required|email',
            'password' => 'required|string'
        ]);
        $user = User::where('email', $fields['email'])->first();

        if (!$user || !Hash::check($fields['password'], $user->password)) {
            return response([
                'message' => 'Bad Credentials'
            ], Response::HTTP_UNAUTHORIZED);
        }

        $token = $user->createToken('ims_token')->plainTextToken;
        $cookie = cookie('jwt', $token, 60 * 24); // 1 Day.

        $response = [
            'message' => 'success',
            'user' => $user,
            'token' => $token
        ];
        return response($response, Response::HTTP_CREATED)->withCookie($cookie);
    }

    public function logout()
    {
        auth()->user()->tokens()->delete();

        $cookie = Cookie::forget('jwt');

        return response([
            'message' => 'Logged Out'
        ])->withCookie($cookie);
    }
}
