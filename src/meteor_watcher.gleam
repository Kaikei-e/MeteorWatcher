import collectors/osv_collector
import file_manager/csv_treator
import file_manager/osv_file_manager
import gleam/io
import gleam/list
import gleam/result
import gleam/string
import vuln_extractors/vuln_diff_extractors

pub fn main() -> Result(Nil, String) {
  let result = osv_collector.osv_collector()
  let assert Ok(io_result) =
    result
    |> result.map(fn(content) { osv_file_manager.osv_file_manager(content) })
    |> result.map_error(fn(error) { io.println(string.inspect(error)) })

  let assert Ok(_) =
    io_result
    |> result.map_error(fn(error) { io.println(error) })

  io.println("OSV file manager completed")

  let csv_files = csv_treator.get_csv_files("osv_vulnerabilities")
  io.println(
    "CSV files fetched, length: " <> string.inspect(list.length(csv_files)),
  )
  let extract_ids = csv_treator.parse_and_extract_id_from_csv(csv_files)
  io.println(
    "CSV files parsed, length: "
    <> string.inspect(list.length(list.flatten(extract_ids))),
  )
  let diff_ids = vuln_diff_extractors.vuln_diff_extractors(extract_ids)
  io.println(
    "Diff IDs extracted, length: " <> string.inspect(list.length(diff_ids)),
  )
  io.println(string.inspect(diff_ids))
  Ok(Nil)
}
