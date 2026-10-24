// Tests/TestInputValidation.cs
using Microsoft.Data.Sqlite;
using NUnit.Framework;

[TestFixture]
public class TestInputValidation {
    [Test]
    public async Task TestForSQLInjection()
    {
        string databasePath = Path.Combine(
            Path.GetTempPath(),
            Guid.NewGuid().ToString("N") + ".db");
        string connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Pooling = false
        }.ToString();
        const string sqlInjectionPayload = "alice' OR 1=1 --";

        try
        {
            await using (var connection = new SqliteConnection(connectionString))
            {
                await connection.OpenAsync();
                await using var createTable = connection.CreateCommand();
                createTable.CommandText =
                    "CREATE TABLE Users (" +
                    "UserID INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "Username TEXT NOT NULL, " +
                    "Email TEXT NOT NULL, " +
                    "PasswordHash TEXT NOT NULL);";
                await createTable.ExecuteNonQueryAsync();
            }

            var repository = new UserRepository(connectionString);
            await repository.InsertUserAsync("alice", "alice@example.com", "ValidPassword123!");

            Assert.ThrowsAsync<System.ArgumentException>(
                async () => await repository.InsertUserAsync(
                    sqlInjectionPayload,
                    "attacker@example.com",
                    "ValidPassword123!"));

            await using var verifyConnection = new SqliteConnection(connectionString);
            await verifyConnection.OpenAsync();
            await using var verifyCommand = verifyConnection.CreateCommand();
            verifyCommand.CommandText = "SELECT COUNT(*) FROM Users;";
            Assert.That(Convert.ToInt32(await verifyCommand.ExecuteScalarAsync()), Is.EqualTo(1));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(databasePath))
            {
                File.Delete(databasePath);
            }
        }
    }

    [Test]
    public void TestForXSS()
    {
        const string xssPayload = "<script>alert('XSS')</script>";

        Assert.Throws<System.ArgumentException>(
            () => InputValidator.SanitizeUsername(xssPayload));

        string encodedOutput = InputValidator.EncodeForHtml(xssPayload);

        Assert.That(
            encodedOutput,
            Is.EqualTo("&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;"));
    }
}