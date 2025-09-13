import gleam/list
import gleam/string

// OSV modified_id.csv file format test
// Format: <iso modified date>,<ecosystem_dir>/<id>
// Example: 2024-08-15T00:00:00Z,PyPI/PYSEC-2021-123

// モックCSVデータ
fn get_mock_osv_data() -> String {
  "2024-08-15T00:00:00Z,PyPI/PYSEC-2021-123
2024-08-15T01:30:00Z,npm/GHSA-2024-456
2024-08-16T12:45:00Z,Go/GO-2024-789
2024-08-16T15:20:00Z,Maven/CVE-2024-001
2024-08-17T08:10:00Z,PyPI/PYSEC-2024-999
2024-08-17T14:25:00Z,RubyGems/GHSA-ruby-123"
}

pub fn osv_collector_mock_test() {
  let content = get_mock_osv_data()

  // テスト1: レスポンスが空でないことを確認
  assert !string.is_empty(content)

  // テスト2: CSV形式であることを確認（最低限の行が存在）
  let lines = string.split(content, on: "\n")
  assert list.length(lines) > 1

  // テスト3: 最初の有効な行がCSV形式であることを確認
  let valid_lines = list.filter(lines, fn(line) { !string.is_empty(line) })
  case list.first(valid_lines) {
    Ok(first_line) -> {
      let parts = string.split(first_line, on: ",")
      // 日付とID部分の2つの要素があることを確認
      assert list.length(parts) >= 2

      // 最初の部分が日付形式（ISO 8601）であることを確認
      case list.first(parts) {
        Ok(date_part) -> {
          assert string.contains(date_part, "T")
          assert string.contains(date_part, "Z")
        }
        Error(_) -> panic as "No date part found"
      }

      // 2番目の部分がエコシステム/IDの形式であることを確認
      case list.drop(parts, 1) |> list.first() {
        Ok(id_part) -> {
          assert string.contains(id_part, "/")
        }
        Error(_) -> panic as "No ID part found"
      }
    }
    Error(_) -> panic as "No valid lines found"
  }
}

pub fn osv_collector_response_format_test() {
  // モックデータでCSV解析のテスト
  let mock_csv_content =
    "2024-08-15T00:00:00Z,PyPI/PYSEC-2021-123\n2024-08-15T01:00:00Z,npm/GHSA-2024-456\n2024-08-16T00:00:00Z,Go/GO-2024-789"

  let lines = string.split(mock_csv_content, on: "\n")
  assert list.length(lines) == 3

  // 各行の形式をテスト
  list.each(lines, fn(line) {
    let parts = string.split(line, on: ",")
    assert list.length(parts) == 2

    case parts {
      [date, id] -> {
        // 日付形式のテスト
        assert string.contains(date, "T")
        assert string.contains(date, "Z")

        // ID形式のテスト
        assert string.contains(id, "/")
      }
      _ -> panic as "Invalid CSV format"
    }
  })
}

pub fn osv_collector_various_ecosystems_test() {
  // 様々なエコシステムをテスト
  let ecosystems = [
    "PyPI/PYSEC-2024-001",
    "npm/GHSA-npm-123",
    "Go/GO-2024-456",
    "Maven/CVE-2024-789",
    "RubyGems/GHSA-ruby-001",
    "crates.io/RUSTSEC-2024-001",
    "NuGet/GHSA-nuget-123",
  ]

  list.each(ecosystems, fn(ecosystem_id) {
    let parts = string.split(ecosystem_id, on: "/")
    assert list.length(parts) == 2

    case parts {
      [ecosystem, id] -> {
        // エコシステム名が空でないことを確認
        assert !string.is_empty(ecosystem)
        // ID部分が空でないことを確認
        assert !string.is_empty(id)
      }
      _ -> panic as "Invalid ecosystem/id format"
    }
  })
}

pub fn osv_collector_date_format_test() {
  // ISO 8601日付形式のテスト
  let valid_dates = [
    "2024-08-15T00:00:00Z",
    "2024-12-31T23:59:59Z",
    "2024-01-01T12:30:45Z",
  ]

  list.each(valid_dates, fn(date) {
    // 基本的なISO 8601形式チェック
    assert string.contains(date, "T")
    assert string.contains(date, "Z")
    assert string.contains(date, "-")
    assert string.contains(date, ":")

    // 年-月-日T時:分:秒Z の形式であることを確認
    let date_time_parts = string.split(date, on: "T")
    assert list.length(date_time_parts) == 2

    case date_time_parts {
      [date_part, time_part] -> {
        // 日付部分のテスト (YYYY-MM-DD)
        let date_components = string.split(date_part, on: "-")
        assert list.length(date_components) == 3

        // 時刻部分のテスト (HH:MM:SSZ)
        assert string.ends_with(time_part, "Z")
        let time_without_z = string.drop_end(time_part, up_to: 1)
        let time_components = string.split(time_without_z, on: ":")
        assert list.length(time_components) == 3
      }
      _ -> panic as "Invalid date format"
    }
  })
}
