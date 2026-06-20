-- D1 schema for the vacation-home booking calendar.
-- Run once via:  npx wrangler d1 execute vacation-calendar --remote --file=schema.sql

CREATE TABLE IF NOT EXISTS Users (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  Name       TEXT    NOT NULL UNIQUE,
  Password   TEXT    NOT NULL DEFAULT '',
  Role       TEXT    NOT NULL DEFAULT 'other_family',
  DaysPerQuarter INTEGER
);

CREATE TABLE IF NOT EXISTS Reservations (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  Owner      TEXT    NOT NULL,
  Type       TEXT    NOT NULL,
  StartDate  TEXT    NOT NULL,
  EndDate    TEXT    NOT NULL,
  Status     TEXT    NOT NULL DEFAULT 'confirmed',
  Quarter    TEXT    NOT NULL,
  Note       TEXT    NOT NULL DEFAULT '',
  Guests     TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS QuarterState (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  Quarter    TEXT    NOT NULL UNIQUE,
  Phase      TEXT    NOT NULL DEFAULT 'A'
);

CREATE TABLE IF NOT EXISTS Config (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  Key        TEXT    NOT NULL UNIQUE,
  Value      TEXT    NOT NULL DEFAULT ''
);
