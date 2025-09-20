import gleam/dict
import gleam/erlang/process
import gleam/int
import gleam/option.{None, Some}
import gleam/otp/static_supervisor
import gleam/result
import pog
import utils/env

pub fn create_db_supervisor(pool_name: process.Name(pog.Message)) {
  let env_map = case env.load_env(".env") {
    Ok(m) -> m
    Error(_) -> env.load_env(".env.local") |> result.unwrap(or: dict.new())
  }

  let host = case env.get(env_map, "DB_HOST") {
    Some(v) -> v
    None -> "127.0.0.1"
  }
  let database = case env.get(env_map, "DB_NAME") {
    Some(v) -> v
    None -> "postgres"
  }
  let user = case env.get(env_map, "DB_USER") {
    Some(v) -> v
    None -> "postgres"
  }
  let password_opt = env.get(env_map, "DB_PASSWORD")
  let port = case env.get(env_map, "DB_PORT") {
    Some(p) -> {
      case int.parse(p) {
        Ok(n) -> n
        Error(_) -> 5432
      }
    }
    None -> 5432
  }
  let pool_size = case env.get(env_map, "DB_POOL_SIZE") {
    Some(s) -> {
      case int.parse(s) {
        Ok(n) -> n
        Error(_) -> 10
      }
    }
    None -> 10
  }

  let pool_child =
    pog.default_config(pool_name)
    |> pog.host(host)
    |> pog.port(port)
    |> pog.database(database)
    |> pog.user(user)
    |> pog.password(case password_opt {
      Some(pw) -> Some(pw)
      None -> None
    })
    |> pog.pool_size(pool_size)
    |> pog.supervised

  static_supervisor.new(static_supervisor.RestForOne)
  |> static_supervisor.add(pool_child)
  // |> supervisor.add(other)
  // |> supervisor.add(application)
  // |> supervisor.add(children)
  |> static_supervisor.start
}

pub fn get_env_variable(name: String) -> String {
  let env_map = case env.load_env(".env") {
    Ok(m) -> m
    Error(_) -> env.load_env(".env.local") |> result.unwrap(or: dict.new())
  }

  case env.get(env_map, name) {
    Some(v) -> v
    None -> ""
  }
}
