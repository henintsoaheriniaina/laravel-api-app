<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $fields = $request->validate([
            'name' => 'required|max:255',
            'email' => 'email|unique:users',
            'password' => 'confirmed|required',
        ]);

        $user = User::create($fields);
        $token = $user->createToken($user->name)->plainTextToken;
        return [
            "user" => $user,
            "token" => $token
        ];
    }
    public function login(Request $request)
    {
        $fields = $request->validate([
            'email' => 'email|exists:users',
            'password' => 'required',
        ]);
        $user = User::where('email', $fields["email"])->first();
        if (!$user || !Hash::check($fields["password"], $user->password)) {
            return response([
                "message" => "Bad credentials"
            ], 401);
        }
        $token = $user->createToken($user->name)->plainTextToken;
        return [
            "user" => $user,
            "token" => $token
        ];
    }
    public function logout(Request $request)
    {
        $request->user()->tokens()->delete();
        return response([
            "message" => "You are logged out"
        ]);
    }
}
