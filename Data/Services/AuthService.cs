namespace BisleriumCafe.Data.Services
{
    internal class AuthService
    {
        private readonly Repository<User> _userRepository;
        private readonly SessionService _sessionService;

        public User CurrentUser { get; private set; }

        // Constructor that initializes the AuthService with a UserRepository and SessionService
        public AuthService(Repository<User> userRepository, SessionService sessionService)
        {
            _userRepository = userRepository;
            _sessionService = sessionService;
        }

        // Seeds an initial admin user if no users exist in the system
        // Returns the username of the seeded admin user
        public async Task<string> SeedInitialUser()
        {
            // Check if users already exist in the system
            if (_userRepository.GetAll().Count != 0)
            {
                return null;
            }

            // Check if an admin user already exists
            if (_userRepository.Contains(x => x.Role, UserRole.Admin))
            {
                return null;
            }

            string username = "admin", Welcome = "Raaz";
            User user = new()
            {
                UserName = username,
                Email = Welcome,
                FullName = Welcome,
                PasswordHash = Hasher.HashSecret(username),
                Role = UserRole.Admin,
                CreatedBy = Guid.Empty,
            };

            // Add the admin user to the repository
            _userRepository.Add(user);
            await _userRepository.FlushAsync();

            return username;
        }

        // Registers a new user with the given information
        public void Register(string username, string email, string fullname, UserRole role)
        {
            // Check if the username already exists
            if (_userRepository.HasUserName(username))
            {
                throw new Exception(message: "Username already exists!");
            }

            User user = new()
            {
                UserName = username,
                Email = email,
                FullName = fullname,
                PasswordHash = Hasher.HashSecret(username),
                Role = role,
                CreatedBy = CurrentUser.Id,
            };

            // Add the new user to the repository
            _userRepository.Add(user);
        }

        // Logs in a user with the provided username and password
        // Generates a session for the user
        public async Task<bool> Login(string userName, string password, bool stayLoggedIn)
        {
            CurrentUser = _userRepository.Get(x => x.UserName, userName);
            if (CurrentUser == null)
            {
                return false;
            }

            if (Hasher.VerifyHash(password, CurrentUser.PasswordHash))
            {
                Session session = Session.Generate(CurrentUser.Id, stayLoggedIn);
                await _sessionService.SaveSession(session);
                return true;
            }

            return false;
        }

        // Checks if the currently logged-in user is an admin
        public bool IsUserAdmin()
        {
            return CurrentUser.Role == UserRole.Admin;
        }

        // Changes the password for the currently logged-in user
        public void ChangePassword(string oldPassword, string newPassword)
        {
            if (oldPassword == newPassword)
            {
                throw new Exception("New password must be different from current password.");
            }

            CurrentUser.PasswordHash = Hasher.HashSecret(newPassword);
            CurrentUser.HasInitialPassword = false;
        }

        // Logs out the currently logged-in user by deleting the session
        public void LogOut()
        {
            _sessionService.DeleteSession();
            CurrentUser = null;
        }

        // Checks the validity of the session and updates the CurrentUser
        public async Task CheckSession()
        {
            Session session = await _sessionService.LoadSession();
            if (session == null)
            {
                return;
            }

            User user = _userRepository.Get(x => x.Id, session.UserId);
            if (user == null)
            {
                return;
            }

            if (!session.IsValid())
            {
                throw new Exception("Session expired!");
            }

            CurrentUser = user;
        }
    }
}
