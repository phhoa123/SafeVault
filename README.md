# SafeVault

SafeVault is a .NET 10 security exercise containing input validation, SQLite persistence, password authentication, role-based authorization, and NUnit tests.

## Projects

- `SafeVaultApp` contains the validation, repository, authentication, and authorization services.
- `SafeVault.Tests` contains input attack simulations and authentication/authorization tests.
- `database.sql` defines the SQLite `Users` table.
- `webform.html` is a static sample form; it is not connected to an HTTP endpoint in this project.

## Security controls

- Usernames are validated against a strict allowlist; email addresses are format-checked and length-limited.
- Values passed to SQLite are bound as parameters rather than concatenated into SQL statements.
- `PasswordHasher<string>` stores salted password hashes. Login verifies the stored hash and updates hashes when the hasher requests rehashing.
- Role checks allow only the known `Admin` and `User` role names and query the database with parameters. New users default to `User`.
- `EncodeForHtml` encodes text for HTML output. Call it when rendering untrusted values in an HTML text or quoted attribute context; validation alone does not prevent XSS in every output context.
- Role assignment must be restricted to trusted administrative provisioning. Do not accept a role supplied by a public registration form.

The static form is only a UI sample; client-side constraints are not a security boundary. Any future HTTP handler must call the validation and persistence services server-side, encode output for its context, and add appropriate request-forgery protections.

## Database setup

Execute `database.sql` against the SQLite database before using the services. Existing databases need a migration to add the `PasswordHash` and `Role` columns; the schema file creates a new database schema but does not migrate existing data.

## Run tests

```powershell
dotnet test .\SafeVault.Tests\SafeVault.Tests.csproj
```

The NUnit tests cover SQL injection and XSS payload handling, successful and failed authentication, and regular-user/admin access to the admin dashboard.

## Security review and fixes

The reviewed code did not contain a confirmed concatenated-input SQL query. The relevant database methods use parameterized commands. The risks addressed in this exercise were injection-shaped user input, unsafe rendering of user-controlled text, and insecure password storage:

- Validation rejects unsupported username characters and malformed email values.
- SQL injection test input is rejected before insertion; the test also verifies that no extra row was created.
- XSS test input is rejected as a username and HTML-encoded before HTML rendering.
- Passwords are hashed and verified using ASP.NET Core `PasswordHasher<string>`.
- RBAC tests confirm regular users are denied admin dashboard access while admins are allowed.

Copilot assisted with implementing the security controls and NUnit attack scenarios. During verification, it helped resolve a missing SQLite dependency and corrected the async NUnit exception assertion after the first test run exposed it. The final test suite passed locally.

## GitHub repository

This workspace is not currently connected to a Git repository or GitHub remote. To meet a requirement for a GitHub-hosted repository, initialize or connect this workspace to the repository provided for the project, then push the reviewed source and tests. Do not publish database files, credentials, or generated build output.
