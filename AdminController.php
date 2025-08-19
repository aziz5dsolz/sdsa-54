<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Laravel\Socialite\Facades\Socialite;
use App\Models\User;
use App\Models\Backlogs;
use App\Models\BacklogProject;
use App\Models\CoinDistribution;
use App\Models\PaymentSetting;
use App\Models\HistoryLog;
use App\Models\Notification;
use Exception;

class AdminController extends Controller
{
    public function index(Request $request)
    {
        return view('admin.login');
    }
    public function signup(Request $request)
    {
        return view('admin.signup');
    }
    public function signupSubmit(Request $request)
    {

        $validatedData = $request->validate([
            'first_name' => 'required|max:20',
            'last_name' => 'required|max:20',
            'email' => 'required|email|unique:users',
            'password' => [
                'required',
                'string',
                'min:8', // Minimum length of 8 characters
                'regex:/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).+$/',
                'confirmed',
            ],
        ], [
            'password.regex' => 'The  password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
        ]);

        $user = new User;
        $user->first_name = $request->first_name;
        $user->last_name = $request->last_name;
        $user->email = $request->email;
        $user->password = Hash::make($request->password);
        $user->save();
        return response()->json(['status' => 200, 'message' => 'Sign-up successful! You can now sign in']);
    }


    public function loginSubmit(Request $request)
    {
        $validatedData = $request->validate([
            'email' => 'required',
            'password' => 'required',
        ]);

        $email = $request->email;
        $password = $request->password;

        if (Auth::attempt(['email' => $email, 'password' => $password])) {
            $user = Auth::user();

            // Check if user is disabled
            if ($user->status == '0') {
                Auth::logout();
                return response()->json(['status' => 403, 'message' => 'The account has been disabled please contact Admin for further assistance.']);
            }

            // Update last activity timestamp on login
            $user->update([
                'last_activity_at' => now()
            ]);

            // User role-based redirection
            if ($user->role == '0') {
                $redirectUrl = route('admin.dashboard');
            } elseif ($user->role == '1') {
                $redirectUrl = route('admin.dashboard');
            } elseif ($user->role == '2') {
                $redirectUrl = route('user.dashboard');
            } else {
                $redirectUrl = '/';
            }

            return response()->json(['status' => 200, 'message' => 'User login Successfully', 'redirect' => $redirectUrl]);
        } else {
            return response()->json(['status' => 402, 'message' => 'Email and password do not match.']);
        }
    }


    public function logout(Request $request)
    {
        // Set last_activity_at to null on logout to mark as offline
        if (Auth::check()) {
            Auth::user()->update([
                'last_activity_at' => null
            ]);
        }

        // Log out the authenticated user
        Auth::logout();

        // Invalidate the session
        $request->session()->invalidate();

        // Regenerate the session token to prevent CSRF attacks
        $request->session()->regenerateToken();

        // Redirect to the desired page (e.g., login or home page)
        return redirect('/'); // Change '/login' to your desired route
    }

    public function isOnline()
    {
        return $this->last_activity_at &&
            $this->last_activity_at->gt(now()->subMinutes(5)); // Consider active if activity within 5 minutes
    }


    public function sendOtp(Request $request)
    {
        $forgotEmail = $request->forgotEmail;
        $validatedData = $request->validate([
            'forgotEmail' => 'required',
        ]);

        $email = $request->forgotEmail;

        $user = User::where('email', $email)->first();
        if ($user) {
            $name = $user->first_name . ' ' . $user->last_name;
            $otp = rand(100000, 999999);
            $hashOtp = Hash::make($otp);
            $user->otp =  $hashOtp;
            $user->save();
            $mailData = [
                'name' => $name,
                'otp' => $otp,
            ];
            $body = view('email.forgot_password_otp', $mailData);

            sendMail($name, $email, 'Password Reset OTP', $body);
            return response()->json(['status' => 200, 'message' => 'OTP Send in your email']);
        } else {

            return response()->json(['status' => 402, 'message' => 'Email NOT FOUND']);
        }
    }
    public function verifyOtp(Request $request)
    {
        $email = $request->email;
        $otpCode = $request->otpCode;
        $validatedData = $request->validate([
            'email' => 'required',
            'otpCode' => 'required',
        ]);
        $user = User::where('email', $email)->first();
        if (!$user) {
            return response()->json(['status' => 200, 'message' => 'User not found']);
        }


        // Verify OTP
        if (Hash::check($otpCode, $user->otp)) {
            // OTP is correct -> Allow password reset
            return response()->json(['status' => 200, 'message' => 'OTP verified successfully']);
        } else {
            return response()->json(['status' => 402, 'message' => 'Invalid OTP']);
        }
    }
    public function resetPassword(Request $request)
    {
        $email = $request->email;
        $otpCode = $request->otpCode;
        $validatedData = $request->validate([
            'new_password' => [
                'required',
                'string',
                'min:8', // Minimum length of 8 characters
                'regex:/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).+$/', // At least one lowercase, one uppercase, one digit, and one special character
                'confirmed', // Ensures it matches `new_password_confirmation`
            ],
        ], [
            'new_password.regex' => 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
            'new_password.confirmed' => 'The password confirmation does not match.',
        ]);

        $user  = User::where('email', $email)->first();
        if (!$user) {
            return response()->json(['status' => 200, 'message' => 'User not found']);
        }
        $password = Hash::make($request->new_password);
        $user->password = $password;
        $user->save();

        return response()->json(['status' => 200, 'message' => 'Password has been change successfully now you can login']);
    }


    public function dashboard(Request $request)
    {
    //    dd(Auth::user()->id);
        $totalPendingBacklogs = Backlogs::where('status_id', 1)->get();
        $pendingBackLogs = Backlogs::with('user')->where('status_id', 1)->limit(10)->get();
        $totalPendingProjects = BacklogProject::where('status', '0')->get();
        $pendingProjects = BacklogProject::where('status', '0')->limit(10)->get();
        $totalDoingCount = Backlogs::whereNotIn('status_id', [3, 5])->get();
        $totalDoneCount = Backlogs::where('status_id', 5)->get();
        $totalApprovedProjects = BacklogProject::where('status', '1')->get();
        $totalCompletedProjects = BacklogProject::where('status', '3')->get();

        $totalUsers = DB::table('users')->where('role', '2')->count();

        // Get filter parameter
        $userFilter = $request->get('user_filter', 'all'); // 'all' or 'with_field_of_study'

        // Get users based on filter
        $allUsersQuery = User::whereIn('role', ['1', '2'])
            ->select('id', 'first_name', 'last_name', 'image', 'email', 'status', 'created_at', 'last_activity_at');

        if ($userFilter == 'with_field_of_study') {
            $allUsersQuery->whereHas('additionalInfo', function ($query) {
                $query->whereNotNull('field_of_study')
                    ->where('field_of_study', '!=', '');
            });
        }

        $allUsers = $allUsersQuery->orderByRaw('status DESC, created_at DESC')
            ->limit(50)
            ->get();

        // Get users with field of study count for the filter buttons
        $usersWithFieldOfStudy = User::whereIn('role', ['1', '2'])
            ->whereHas('additionalInfo', function ($query) {
                $query->whereNotNull('field_of_study')
                    ->where('field_of_study', '!=', '');
            })->count();

        // Doing with submission count and voting turnout
        $doing = Backlogs::with(['BacklogCategory', 'BacklogStatus', 'User'])
            ->whereNotIn('backlogs.status_id', [3, 5])->limit(10)->get();

        // Manually add counts with correct property names
        $doing = $doing->map(function ($backlog) use ($totalUsers) {
            // Get submission count (use submissions_count to match Blade template)
            $backlog->submissions_count = BacklogProject::where('backlog_id', $backlog->id)->count();

            // Get voting turnout (distinct users who voted)
            $backlog->voting_turn_out = DB::table('votes')
                ->join('backlog_projects', 'votes.project_id', '=', 'backlog_projects.id')
                ->where('backlog_projects.backlog_id', $backlog->id)
                ->distinct('votes.user_id')
                ->count('votes.user_id');

            $backlog->total_users = $totalUsers;
            $backlog->voting_percentage = $totalUsers > 0
                ? ($backlog->voting_turn_out / $totalUsers) * 100
                : 0;

            return $backlog;
        });

        // Done with submission count and voting turnout
        $done = Backlogs::with(['BacklogCategory', 'BacklogStatus', 'User'])
            ->where('backlogs.status_id', '=', 5)->limit(10)->get();

        $done = $done->map(function ($backlog) use ($totalUsers) {
            // Get submission count (use submissions_count to match Blade template)
            $backlog->submissions_count = BacklogProject::where('backlog_id', $backlog->id)->count();

            // Get voting turnout (distinct users who voted)
            $backlog->voting_turn_out = DB::table('votes')
                ->join('backlog_projects', 'votes.project_id', '=', 'backlog_projects.id')
                ->where('backlog_projects.backlog_id', $backlog->id)
                ->distinct('votes.user_id')
                ->count('votes.user_id');

            $backlog->total_users = $totalUsers;
            $backlog->voting_percentage = $totalUsers > 0
                ? ($backlog->voting_turn_out / $totalUsers) * 100
                : 0;

            return $backlog;
        });


        // Approved Projects (status 1 = approved)
        $approvedProjects = BacklogProject::with(['User', 'Backlog'])
            ->where('status', '1')
            ->withCount([
                'votes as total_votes'
            ])->limit(10)->get();

        // Completed Projects (status 3 = completed)
        $completedProjects = BacklogProject::with(['User', 'Backlog'])
            ->where('status', '3')
            ->withCount([
                'votes as total_votes'
            ])->limit(10)
            ->get();

        $totalProjects = BacklogProject::with(['User', 'Backlog'])
            ->whereIn('status', ['0', '1', '3'])
            ->withCount([
                'votes as total_votes'
            ])->get();

        $total_coins = PaymentSetting::find(1)->total_yearly_tokens;

        $distributed_to_solver = CoinDistribution::where('status', 'completed')
            ->where('reference_type', 'App\Models\BacklogProject')
            ->sum(DB::raw('CAST(amount AS DECIMAL(18,8))'));

        $distributed_to_reviewer = CoinDistribution::where('status', 'completed')
            ->where('reference_type', 'App\Models\Vote')
            ->sum(DB::raw('CAST(amount AS DECIMAL(18,8))'));

        $coinDistribution = [
            'total_coins' => $total_coins,
            'distributed_to_solver' => $distributed_to_solver,
            'distributed_to_reviewer' => $distributed_to_reviewer,
        ];

        $latestActions = HistoryLog::with('user')->orderBy('created_at', 'asc')->get();

        return view('admin.dashboard', compact(
            'pendingBackLogs',
            'pendingProjects',
            'doing',
            'done',
            'approvedProjects',        // NEW: Pass approved projects
            'completedProjects',       // NEW: Pass completed projects
            'coinDistribution',
            'latestActions',
            'totalUsers',
            'allUsers',
            'usersWithFieldOfStudy',
            'totalProjects',
            'totalPendingBacklogs',
            'totalPendingProjects',
            'totalDoingCount',
            'totalDoneCount',
            'totalApprovedProjects',
            'totalCompletedProjects'
        ));
    }


    public function redirectToGoogle()

    {

        return Socialite::driver('google')->redirect();
    }
    public function handleGoogleCallback()

    {

        try {



            $user = Socialite::driver('google')->user();



            $finduser = User::where('google_id', $user->id)->first();



            if ($finduser) {



                Auth::login($finduser);



                return redirect()->intended('dashboard');
            } else {


                $fullName = $user->name;
                $nameParts = explode(' ', $fullName, 2);

                $firstName = $nameParts[0] ?? null;
                $lastName = $nameParts[1] ?? null;
                $email = $user->email;
                $newUser = new User;
                $newUser->first_name = $firstName;
                $newUser->last_name = $lastName;
                $newUser->email = $email;
                $newUser->google_id = $user->id;
                $newUser->password = '';
                $newUser->save();
                Auth::login($newUser);

                return redirect()->intended('dashboard');
            }
        } catch (Exception $e) {

            dd($e->getMessage());
        }
    }


    public function profile(Request $request)
    {
        return view('admin.profile');
    }


    public function coin_distribution(Request $request)
    {
        return view('admin.coin_distribution');
    }

    public function notification(Request $request)
    {
        $data['notifications'] = Notification::where('notify_to', Auth()->user()->id)->with(['user'])->orderBy('id', 'desc')->get();

        return view('admin.notification')->with($data);
    }
}
