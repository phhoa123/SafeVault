using Microsoft.Data.Sqlite;

namespace SafeVault.Tests;

[TestFixture]
public sealed class AuthAndAuthorizationTests
{
    private const string RegularUserPassword = "CorrectHorseBatteryStaple!";
    private const string AdminPassword = "AnotherCorrectHorseBatteryStaple!";

    private string _databasePath = null!;
    private string _connectionString = null!;

    [SetUp]
    public async Task SetUp()
    {
        _databasePath = Path.Combine(
            Path.GetTempPath(),
            Guid.NewGuid().ToString("N") + ".db");
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Pooling = false
        }.ToString();

        await using (var connection = new SqliteConnection(_connectionString))
        {
            await connection.OpenAsync();
            await using var createTable = connection.CreateCommand();
            createTable.CommandText =
                "CREATE TABLE Users (" +
                "UserID INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "Username TEXT NOT NULL, " +
                "Email TEXT NOT NULL, " +
                "PasswordHash TEXT NOT NULL, " +
                "Role TEXT NOT NULL DEFAULT 'User' CHECK (Role IN ('Admin', 'User')));";
            await createTable.ExecuteNonQueryAsync();
        }

        var userRepository = new UserRepository(_connectionString);
        await userRepository.InsertUserAsync(
            "alice",
            "alice@example.com",
            RegularUserPassword);
        await userRepository.InsertUserAsync(
            "admin",
            "admin@example.com",
            AdminPassword);

        await using (var connection = new SqliteConnection(_connectionString))
        {
            await connection.OpenAsync();
            await using var setAdminRole = connection.CreateCommand();
            setAdminRole.CommandText =
                "UPDATE Users SET Role = @Role WHERE Username = @Username;";
            setAdminRole.Parameters.AddWithValue("@Role", AuthorizationService.AdminRole);
            setAdminRole.Parameters.AddWithValue("@Username", "admin");
            await setAdminRole.ExecuteNonQueryAsync();
        }
    }

    [TearDown]
    public void TearDown()
    {
        SqliteConnection.ClearAllPools();
        if (File.Exists(_databasePath))
        {
            File.Delete(_databasePath);
        }
    }

    [Test]
    public async Task AuthenticateAsyncReturnsTrueForValidCredentials()
    {
        var authService = new AuthService(_connectionString);

        bool authenticated = await authService.AuthenticateAsync("alice", RegularUserPassword);

        Assert.That(authenticated, Is.True);
    }

    [Test]
    public async Task AuthenticateAsyncReturnsFalseForIncorrectPassword()
    {
        var authService = new AuthService(_connectionString);

        bool authenticated = await authService.AuthenticateAsync("alice", "wrong-password");

        Assert.That(authenticated, Is.False);
    }

    [Test]
    public async Task AuthenticateAsyncReturnsFalseForUnknownUsername()
    {
        var authService = new AuthService(_connectionString);

        bool authenticated = await authService.AuthenticateAsync("unknown", RegularUserPassword);

        Assert.That(authenticated, Is.False);
    }

    [Test]
    public async Task RegularUserCannotAccessAdminDashboard()
    {
        var authorizationService = new AuthorizationService(_connectionString);

        bool allowed = await authorizationService.CanAccessAdminDashboardAsync("alice");

        Assert.That(allowed, Is.False);
    }

    [Test]
    public async Task AdminCanAccessAdminDashboard()
    {
        var authorizationService = new AuthorizationService(_connectionString);

        bool allowed = await authorizationService.CanAccessAdminDashboardAsync("admin");

        Assert.That(allowed, Is.True);
    }
}
