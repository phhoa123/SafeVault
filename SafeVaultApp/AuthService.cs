using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;

public sealed class AuthService
{
    private readonly string _connectionString;
    private readonly IPasswordHasher<string> _passwordHasher;
    private readonly string _dummyPasswordHash;

    public AuthService(
        string connectionString,
        IPasswordHasher<string>? passwordHasher = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new ArgumentException("A connection string is required.", nameof(connectionString));
        }

        _connectionString = connectionString;
        _passwordHasher = passwordHasher ?? new PasswordHasher<string>();
        _dummyPasswordHash = _passwordHasher.HashPassword(string.Empty, Guid.NewGuid().ToString("N"));
    }

    public string HashPassword(string username, string password)
    {
        string normalizedUsername = InputValidator.SanitizeUsername(username);
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Password is required.", nameof(password));
        }

        return _passwordHasher.HashPassword(normalizedUsername, password);
    }

    public async Task<bool> AuthenticateAsync(
        string? username,
        string? password,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
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

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT PasswordHash FROM Users WHERE Username = @Username LIMIT 1;";
        command.Parameters.Add("@Username", SqliteType.Text).Value = normalizedUsername;

        object? result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        if (result is not string passwordHash)
        {
            _passwordHasher.VerifyHashedPassword(normalizedUsername, _dummyPasswordHash, password);
            return false;
        }

        PasswordVerificationResult verificationResult =
            _passwordHasher.VerifyHashedPassword(normalizedUsername, passwordHash, password);
        if (verificationResult == PasswordVerificationResult.Failed)
        {
            return false;
        }

        if (verificationResult == PasswordVerificationResult.SuccessRehashNeeded)
        {
            string updatedHash = _passwordHasher.HashPassword(normalizedUsername, password);
            await using var updateCommand = connection.CreateCommand();
            updateCommand.CommandText =
                "UPDATE Users SET PasswordHash = @NewPasswordHash " +
                "WHERE Username = @Username AND PasswordHash = @CurrentPasswordHash;";
            updateCommand.Parameters.Add("@NewPasswordHash", SqliteType.Text).Value = updatedHash;
            updateCommand.Parameters.Add("@Username", SqliteType.Text).Value = normalizedUsername;
            updateCommand.Parameters.Add("@CurrentPasswordHash", SqliteType.Text).Value = passwordHash;
            await updateCommand.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        return true;
    }
}