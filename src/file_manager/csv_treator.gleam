import gleam/int
import gleam/io
import gleam/list
import gleam/order
import gleam/result
import gleam/string
import gleam/time/calendar
import gleam/time/duration
import gleam/time/timestamp
import simplifile

pub fn get_csv_files(directory_path: String) -> List(String) {
  io.println("Getting CSV files from directory: " <> directory_path)
  case simplifile.read_directory(directory_path) {
    Ok(files) -> {
      let csv_files =
        list.filter(files, fn(name) { string.ends_with(name, ".csv") })
      take_latest_two_names(csv_files)
      |> list.map(fn(name) { directory_path <> "/" <> name })
    }
    Error(_) -> []
  }
}

pub fn take_latest_two_names(names: List(String)) -> List(String) {
  let sorted_desc = list.sort(names, by: fn(a, b) { string.compare(b, a) })
  list.take(sorted_desc, up_to: 2)
}

pub fn get_today_date() -> String {
  // gleam_timeライブラリを使用してシステム時刻から動的に今日の日付を取得
  let now = timestamp.system_time()
  let #(date, _time) = timestamp.to_calendar(now, calendar.utc_offset)
  format_date_to_string(date)
}

fn format_date_to_string(date: calendar.Date) -> String {
  let year_str = int.to_string(date.year)
  let month_str = format_month_to_string(date.month)
  let day_str = case date.day < 10 {
    True -> "0" <> int.to_string(date.day)
    False -> int.to_string(date.day)
  }
  year_str <> "-" <> month_str <> "-" <> day_str
}

fn format_month_to_string(month: calendar.Month) -> String {
  case month {
    calendar.January -> "01"
    calendar.February -> "02"
    calendar.March -> "03"
    calendar.April -> "04"
    calendar.May -> "05"
    calendar.June -> "06"
    calendar.July -> "07"
    calendar.August -> "08"
    calendar.September -> "09"
    calendar.October -> "10"
    calendar.November -> "11"
    calendar.December -> "12"
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

fn get_days_ago_date(_today: String, days: Int) -> String {
  // gleam_timeライブラリを使用して正確に指定日数前の日付を計算
  let now = timestamp.system_time()
  let hours_to_subtract = 24 * days
  let past_duration = duration.hours(-hours_to_subtract)
  let past_timestamp = timestamp.add(now, past_duration)
  let #(date, _time) =
    timestamp.to_calendar(past_timestamp, calendar.utc_offset)
  format_date_to_string(date)
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
