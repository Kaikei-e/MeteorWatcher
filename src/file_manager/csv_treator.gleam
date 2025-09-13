import gleam/int
import gleam/io
import gleam/list
import gleam/order
import gleam/result
import gleam/string
import simplifile

pub fn get_csv_files(directory_path: String) -> List(String) {
  io.println("Getting CSV files from directory: " <> directory_path)
  case simplifile.read_directory(directory_path) {
    Ok(files) ->
      take_latest_two_names(files)
      |> list.map(fn(name) { directory_path <> "/" <> name })
    Error(_) -> []
  }
}

pub fn take_latest_two_names(names: List(String)) -> List(String) {
  let sorted_desc = list.sort(names, by: fn(a, b) { string.compare(b, a) })
  list.take(sorted_desc, up_to: 2)
}

pub fn get_today_date() -> String {
  // 最新のCSVファイル名から日付を推定
  case simplifile.read_directory("osv_vulnerabilities") {
    Ok(files) -> {
      let sorted_files = list.sort(files, by: fn(a, b) { string.compare(b, a) })
      case list.first(sorted_files) {
        Ok(latest_file) -> extract_date_from_filename(latest_file)
        Error(_) -> "2025-09-13"
        // フォールバック
      }
    }
    Error(_) -> "2025-09-13"
    // フォールバック
  }
}

fn extract_date_from_filename(filename: String) -> String {
  // ファイル名形式: 2025-09-13T21_28_49.916286127Z09_00.csv
  // から 2025-09-13 を抽出
  case string.split(filename, on: "T") {
    [date_part, ..] -> date_part
    _ -> "2025-09-13"
    // フォールバック
  }
}

// 今日から4日以内のCSVレコードのみフィルタ
// レコード形式: "YYYY-MM-DD,CVEID"
pub fn filter_recent_days(
  csv_records: List(String),
  today: String,
) -> List(String) {
  list.filter(csv_records, fn(record) {
    case string.split(record, on: ",") {
      [date_part, _cveid] -> is_within_week(date_part, today)
      _ -> False
    }
  })
}

fn is_within_week(date: String, today: String) -> Bool {
  // 簡単な文字列比較で4日以内かチェック
  // 例: "2025-09-13" から "2025-09-09" 以降
  let days_ago = get_days_ago_date(today, 4)
  string.compare(date, days_ago) != order.Lt
}

fn get_days_ago_date(today: String, days: Int) -> String {
  // 簡易実装: 日付から指定日数を引く（月またぎは考慮しない）
  case string.split(today, on: "-") {
    [year, month, day] -> {
      case int.parse(day) {
        Ok(d) if d > days -> {
          let new_day = d - days
          let day_str = case new_day < 10 {
            True -> "0" <> int.to_string(new_day)
            False -> int.to_string(new_day)
          }
          year <> "-" <> month <> "-" <> day_str
        }
        _ -> "2025-09-01"
        // フォールバック
      }
    }
    _ -> "2025-09-01"
  }
}

pub fn parse_and_extract_id_from_csv(file: List(String)) -> List(List(String)) {
  io.println(
    "Parsing and extracting ID from CSV files, length: "
    <> string.inspect(list.length(file)),
  )

  let lines_result =
    list.map(file, fn(file) {
      simplifile.read(from: file)
      |> result.map(fn(content) { string.split(content, on: "\n") })
    })
    |> list.map(fn(lines_result) {
      case lines_result {
        Ok(lines) -> lines
        Error(_) -> []
      }
    })

  io.println(
    "Lines parsed, length: "
    <> string.inspect(list.length(list.flatten(lines_result))),
  )

  // 今日の日付をシステムから取得
  let today = get_today_date()

  list.map(lines_result, fn(lines) {
    // 4日以内のCSVレコードのみフィルタ
    let recent_records = filter_recent_days(lines, today)
    io.println(
      "Recent records (within 4 days), length: "
      <> string.inspect(list.length(recent_records)),
    )

    // フィルタ後のレコードからCVEIDのみを抽出
    let ids =
      list.map(recent_records, fn(record) {
        case string.split(record, on: ",") {
          [_date, cveid] -> cveid
          _ -> record
          // フォールバック
        }
      })

    io.println(
      "CVE IDs extracted, length: " <> string.inspect(list.length(ids)),
    )

    ids
  })
}
