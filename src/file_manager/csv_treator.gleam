import gleam/list
import gleam/result
import gleam/string
import simplifile

pub fn get_csv_files(directory_path: String) -> List(String) {
  case simplifile.read_directory(directory_path) {
    Ok(files) -> files
    Error(_) -> []
  }
}

pub fn parse_csv(file: String) -> List(String) {
  let lines_result =
    simplifile.read(from: file)
    |> result.map(fn(content) { string.split(content, on: "\n") })

  case lines_result {
    Ok(lines) ->
      list.map(lines, fn(line) {
        case string.split(line, on: ",") |> list.last {
          Ok(id) -> id
          Error(_) -> line
        }
      })
    Error(_) -> []
  }
}
