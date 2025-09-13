import collectors/osv_collector
import file_manager/osv_file_manager
import gleam/io
import gleam/result
import gleam/string

pub fn main() -> Result(Nil, String) {
  let result = osv_collector.osv_collector()
  let assert Ok(io_result) =
    result
    |> result.map(fn(content) { osv_file_manager.osv_file_manager(content) })
    |> result.map_error(fn(error) { io.println(string.inspect(error)) })

  let assert Ok(_) =
    io_result
    |> result.map_error(fn(error) { io.println(error) })

  Ok(Nil)
}
