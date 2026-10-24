using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;

public sealed class UserRepository
{
    private readonly string _connectionString;
    private readonly IPasswordHasher<string> _passwordHasher;

    public UserRepository(
        string connectionString,
        IPasswordHasher<string>? passwordHasher = null)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new ArgumentException("A connection string is required.", nameof(connectionString));
        }

        _connectionString = connectionString;
        _passwordHasher = passwordHasher ?? new PasswordHasher<string>();
    }

    public async Task InsertUserAsync(
        string username,
        string email,
        string password,
        CancellationToken cancellationToken = default)
    {
        string validatedUsername = InputValidator.SanitizeUsername(username);
        string validatedEmail = InputValidator.SanitizeEmail(email);
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Password is required.", nameof(password));
        }

        string passwordHash = _passwordHasher.HashPassword(validatedUsername, password);

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        await using var command = connection.CreateCommand();
        command.CommandText =
            "INSERT INTO Users (Username, Email, PasswordHash) " +
            "VALUES (@Username, @Email, @PasswordHash);";
        command.Parameters.Add("@Username", SqliteType.Text).Value = validatedUsername;
        command.Parameters.Add("@Email", SqliteType.Text).Value = validatedEmail;
        command.Parameters.Add("@PasswordHash", SqliteType.Text).Value = passwordHash;

        int rowsInserted = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        if (rowsInserted != 1)
        {
            throw new InvalidOperationException("The user record was not inserted.");
        }
    }
}