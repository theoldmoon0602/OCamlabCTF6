create table if not exists users (
    id integer primary key,
    name text not null unique,
    password_hash text not null,
    team_id text not null,
    is_admin integer default 0,
    icon blob default null
);

create table if not exists teams (
    id integer primary key,
    name text not null unique,
    icon blob default null,
    token text not null
);

create table if not exists categories (
    id integer primary key,
    name text not null unique
);

create table if not exists challenges (
    id integer primary key,
    name text not null unique,
    c_id integer not null,
    description text not null,
    flag text not null unique,
    point integer not null,
    is_open integer default 1
);

create table if not exists submissions (
    id integer primary key,
    u_id integer not null,
    p_id integer not null,
    flag text not null,
    point integer not null,
    is_correct integer not null,
    created_at integer not null
);

create table if not exists competition (
  name text not null,
  start_at integer not null,
  end_at integer not null,
  enabled integer not null default 0
);
