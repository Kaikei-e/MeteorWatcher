import file_manager/csv_treator.{
  filter_recent_days, get_today_date, take_latest_two_names,
}
import gleam/list
import gleam/string

pub fn take_latest_two_names_test() {
  let names = [
    "2025-09-13T17_37_59.csv",
    "2025-09-13T21_14_05.csv",
    "2025-09-13T19_40_17.csv",
  ]

  let expected = ["2025-09-13T21_14_05.csv", "2025-09-13T19_40_17.csv"]
  let actual = take_latest_two_names(names)

  assert expected == actual
}

pub fn filter_recent_week_test() {
  let csv_records = [
    "2025-09-09,PyPI/OLD-123",
    // 4日前（境界、含む）
    "2025-09-08,PyPI/OLD-124",
    // 5日前（除外）
    "2025-09-10,PyPI/NEW-123",
    // 3日前（含む）
    "2025-09-13,PyPI/NEW-124",
    // 当日（含む）
    "2025-09-07,PyPI/VERY-OLD",
    // 6日前（除外）
    "2025-09-12,PyPI/RECENT",
    // 1日前（含む）
  ]

  // 2025-09-13 基準で4日以内（2025-09-09以降）のみ
  let expected = [
    "2025-09-09,PyPI/OLD-123",
    "2025-09-10,PyPI/NEW-123",
    "2025-09-13,PyPI/NEW-124",
    "2025-09-12,PyPI/RECENT",
  ]

  let actual = filter_recent_days(csv_records, "2025-09-13")

  assert expected == actual
}

pub fn get_today_date_test() {
  let today = get_today_date()

  // 日付形式が YYYY-MM-DD であることをチェック
  let parts = string.split(today, on: "-")
  assert list.length(parts) == 3

  // 年が4桁、月・日が2桁であることをチェック
  case parts {
    [year, month, day] -> {
      assert string.length(year) == 4
      assert string.length(month) == 2
      assert string.length(day) == 2
    }
    _ -> panic as "Invalid date format"
  }
}
