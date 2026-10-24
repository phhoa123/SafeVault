using System;
using System.Net;
using System.Net.Mail;
using System.Text.RegularExpressions;

public static class InputValidator
{
    private static readonly Regex UsernamePattern = new Regex(
        @"\A[A-Za-z0-9_.-]{3,32}\z",
        RegexOptions.CultureInvariant);

    /// <summary>
    /// Validates and trims a username. Encode the result for its output context, and use
    /// parameterized queries when storing or querying it.
    /// </summary>
    public static string SanitizeUsername(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            throw new ArgumentException("Username is required.", nameof(username));
        }

        string normalizedUsername = username.Trim();
        if (!UsernamePattern.IsMatch(normalizedUsername))
        {
            throw new ArgumentException(
                "Username must be 3 to 32 characters and contain only letters, numbers, periods, underscores, or hyphens.",
                nameof(username));
        }

        return normalizedUsername;
    }

    /// <summary>
    /// Validates and trims an email address. Encode the result for its output context, and use
    /// parameterized queries when storing or querying it.
    /// </summary>
    public static string SanitizeEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            throw new ArgumentException("Email is required.", nameof(email));
        }

        string normalizedEmail = email.Trim();
        if (normalizedEmail.Length > 254 ||
            normalizedEmail.IndexOfAny(new[] { ' ', '\t', '\r', '\n' }) >= 0)
        {
            throw new ArgumentException("Email address is invalid.", nameof(email));
        }

        try
        {
            var parsedAddress = new MailAddress(normalizedEmail);
            if (!string.Equals(parsedAddress.Address, normalizedEmail, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("Email address is invalid.", nameof(email));
            }
        }
        catch (FormatException)
        {
            throw new ArgumentException("Email address is invalid.", nameof(email));
        }

        return normalizedEmail;
    }

    /// <summary>
    /// HTML-encodes text for insertion into an HTML text or quoted attribute context.
    /// </summary>
    public static string EncodeForHtml(string value)
    {
        if (value == null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        return WebUtility.HtmlEncode(value);
    }
}