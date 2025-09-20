import gleam/dict
import gleam/list
import gleam/option
import gleam/string
import simplifile

pub type EnvMap =
  dict.Dict(String, String)

fn parse_line(line: String) -> Result(#(String, String), Nil) {
  let trimmed = string.trim(line)
  case trimmed {
    "" -> Error(Nil)
    _ -> {
      case string.starts_with(trimmed, "#") {
        True -> Error(Nil)
        False -> {
          case string.split(trimmed, on: "=") {
            [key, value] -> {
              let k = string.trim(key)
              let v1 = string.trim(value)
              let v = case
                string.starts_with(v1, "\""),
                string.ends_with(v1, "\"")
              {
                True, True -> string.slice(v1, 1, string.length(v1) - 1)
                _, _ -> v1
              }
              Ok(#(k, v))
            }
            _ -> Error(Nil)
          }
        }
      }
    }
  }
}

pub fn load_env(file_path: String) -> Result(EnvMap, String) {
  case simplifile.read(file_path) {
    Ok(content) -> {
      let pairs =
        string.split(content, on: "\n")
        |> list.filter_map(parse_line)
      Ok(dict.from_list(pairs))
    }
    Error(_) -> Error("Failed to read .env file")
  }
}

pub fn get(env: EnvMap, key: String) -> option.Option(String) {
  case dict.get(env, key) {
    Ok(v) -> option.Some(v)
    Error(_) -> option.None
  }
}
