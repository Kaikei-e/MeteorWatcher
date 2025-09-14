import collectors/actual_vulnerability_collector
import collectors/osv_collector
import file_manager/csv_treator
import file_manager/osv_file_manager
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/io
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import index_searcher/searcher
import index_searcher/vuln_index_loader
import simplifile
import vuln_extractors/vuln_diff_extractors

pub type TargetConfig {
  TargetConfig(scan_targets: List(String))
}

fn load_target_config() -> Result(TargetConfig, String) {
  use content <- result.try(
    simplifile.read("target.json")
    |> result.map_error(fn(_) { "Failed to read target.json" }),
  )

  let decoder = {
    use scan_targets <- decode.field("scan_targets", decode.list(decode.string))
    decode.success(TargetConfig(scan_targets:))
  }

  json.parse(from: content, using: decoder)
  |> result.map_error(fn(_) { "Failed to parse target.json" })
}

pub fn main() -> Result(Nil, String) {
  use config <- result.try(load_target_config())

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

  let newly_found_vulnerabilities =
    list.map(diff_ids, fn(id) {
      // Sleep for 5 seconds for being polite
      io.println("Sleeping for 5 seconds")
      process.sleep(5000)
      case actual_vulnerability_collector.fetch_and_decode_vulnerability(id) {
        Ok(osv_vulnerability) -> osv_vulnerability
        Error(e) -> {
          io.println("Error: " <> e)
          None
        }
      }
    })
    |> list.append([])
    // Filter out None
    |> list.filter_map(fn(maybe_osv_vulnerability) {
      case maybe_osv_vulnerability {
        Some(osv_vulnerability) -> Ok(osv_vulnerability)
        None -> {
          io.println("None")
          Error(Nil)
        }
      }
    })

  io.println(string.inspect(newly_found_vulnerabilities))

  let index = searcher.create_vuln_index()
  let assert Ok(count) =
    vuln_index_loader.build_index_from_target_vulnerabilities(
      index,
      newly_found_vulnerabilities,
    )

  io.println("Index built, count: " <> string.inspect(count))

  // 各ターゲットディレクトリをスキャン
  let all_matches =
    list.fold(config.scan_targets, [], fn(acc, target_dir) {
      io.println("Scanning directory: " <> target_dir)
      case searcher.scan_directory_sequential(index, target_dir) {
        Ok(matches) -> {
          io.println(
            "Found "
            <> string.inspect(list.length(matches))
            <> " matches in "
            <> target_dir,
          )
          list.append(acc, matches)
        }
        Error(e) -> {
          io.println("Error scanning " <> target_dir <> ": " <> e)
          acc
        }
      }
    })

  io.println(
    "Total matches found: " <> string.inspect(list.length(all_matches)),
  )
  io.println("All matches: " <> string.inspect(all_matches))

  Ok(Nil)
}
