import filepath
import gleam/io
import gleam/result
import gleam/string
import gleam/time/duration
import gleam/time/timestamp
import simplifile

pub fn osv_file_manager(file_body: String) -> Result(Nil, String) {
  let jst = duration.hours(9)

  let now =
    timestamp.system_time()
    |> fn(time) { timestamp.to_rfc3339(time, jst) }
    |> fn(time) { string.replace(time, ":", "_") }
    |> fn(time) { string.replace(time, "+", "Z") }

  let file_name: String = filepath.join("osv_vulnerabilities", now <> ".csv")

  let assert Ok(_) =
    file_body
    |> simplifile.write(to: file_name)
    |> result.map_error(fn(error) {
      "Failed to write file " <> string.inspect(error)
    })

  io.println("File written to " <> file_name)

  Ok(Nil)
}
