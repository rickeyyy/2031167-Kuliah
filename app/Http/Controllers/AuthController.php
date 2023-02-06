<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    public function register(Request $request){
        $data = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
            'password' => ['required', 'string', 'min:8'],
        ]);

        $data['password'] = Hash::make($request->password);
        $data['is_admin'] = $request->is_admin ?? false;

        $user = User::create($data);

        if (!Auth::attempt($request->only('email','password'))){
            return response()->json([
                'message' => 'Invalid Credentials'
            ], 401);
        }

        $token = $user->createToken('auth_token')->plainTextToken;
        return response()->json([
            'message'=> 'success',
            'data' => $user,
            'meta' => [
                'token' => $token
            ]
        ],201);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        $user = User::where('email', $request['email'])->first();
        if ($user == null) {
            return response()->json([
                'message' => 'Invalid Credentials'
            ], 401);
        }

        $token = $user->createToken('token')->plainTextToken;
        return response()->json([
            'message'=> 'success',
            'data' => $user,
            'meta' => [
                'token' => $token
            ]
        ],200);
    }

    public function logout(Request $request){
        $request->user()->tokens()->delete();
        return response()->json([
            'message'=> 'success',
        ],200); 
    }
}
