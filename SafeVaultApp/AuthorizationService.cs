using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;

public sealed class AuthorizationService
{
    public const string AdminRole = "Admin";
    public const string UserRole = "User";

    private readonly string _connectionString;

    public AuthorizationService(string connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new ArgumentException("A connection string is required.", nameof(connectionString));
        }

        _connectionString = connectionString;
    }

    public async Task<bool> IsInRoleAsync(
        string? username,
        string? role,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(role))
        {
            return false;
        }

        string normalizedUsername;
        try
        {
            normalizedUsername = InputValidator.SanitizeUsername(username);
        }
        catch (ArgumentException)
        {
            return false;
        }

        string normalizedRole;
        if (string.Equals(role, AdminRole, StringComparison.OrdinalIgnoreCase))
        {
            normalizedRole = AdminRole;
        }
        else if (string.Equals(role, UserRole, StringComparison.OrdinalIgnoreCase))
        {
            normalizedRole = UserRole;
        }
        else
        {
            return false;
        }

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        await using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT EXISTS (" +
            "SELECT 1 FROM Users WHERE Username = @Username AND Role = @Role);";
        command.Parameters.Add("@Username", SqliteType.Text).Value = normalizedUsername;
        command.Parameters.Add("@Role", SqliteType.Text).Value = normalizedRole;

        object? result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return Convert.ToInt64(result) == 1;
    }

    public Task<bool> CanAccessAdminFeatureAsync(
        string? username,
        CancellationToken cancellationToken = default)
    {
        return IsInRoleAsync(username, AdminRole, cancellationToken);
    }

    public Task<bool> CanAccessAdminDashboardAsync(
        string? username,
        CancellationToken cancellationToken = default)
    {
        return IsInRoleAsync(username, AdminRole, cancellationToken);
    }
}