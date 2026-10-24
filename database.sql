-- database.sql
CREATE TABLE Users (
    UserID INTEGER PRIMARY KEY AUTOINCREMENT,
    Username TEXT NOT NULL,
    Email TEXT NOT NULL,
    PasswordHash TEXT NOT NULL,
    Role TEXT NOT NULL DEFAULT 'User' CHECK (Role IN ('Admin', 'User'))
);