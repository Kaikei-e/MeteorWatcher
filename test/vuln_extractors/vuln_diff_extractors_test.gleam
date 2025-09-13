// recieve the directory where stores the csv files directory path and compare the 4 csv files and the latest csv file
// and extract the vulnerabilities that are new or changed
// test is here

// ファイルは積み上げ形式

import vuln_extractors/vuln_diff_extractors.{vuln_diff_extractors}

pub fn vuln_diff_extractors_test() {
  let first_file_content = [
    "2024-08-15T00:00:00Z,PyPI/PYSEC-2021-123",
    "2024-08-15T00:00:00Z,PyPI/PYSEC-2021-124",
  ]
  let second_file_content = [
    "2024-08-16T00:00:00Z,Go/GOSEC-2021-123",
    "2024-08-16T00:00:00Z,Go/GOSEC-2021-124",
    "2024-08-15T00:00:00Z,PyPI/PYSEC-2021-123",
    "2024-08-15T00:00:00Z,PyPI/PYSEC-2021-124",
  ]
  let third_file_content = [
    "2024-08-17T00:00:00Z,Rust/RUSTSEC-2021-123",
    "2024-08-17T00:00:00Z,Rust/RUSTSEC-2021-124",
    "2024-08-17T00:00:00Z,Go/GOSEC-2021-123",
    "2024-08-17T00:00:00Z,Go/GOSEC-2021-124",
    "2024-08-15T00:00:00Z,PyPI/PYSEC-2021-123",
    "2024-08-15T00:00:00Z,PyPI/PYSEC-2021-124",
  ]
  let latest_file_content = [
    "2024-08-15T00:00:00Z,Ruby/RUBYSEC-2021-123",
    "2024-08-15T00:00:00Z,Ruby/RUBYSEC-2021-124",
    "2024-08-15T00:00:00Z,Go/GOSEC-2021-123",
    "2024-08-15T00:00:00Z,Go/GOSEC-2021-124",
    "2024-08-15T00:00:00Z,Rust/RUSTSEC-2021-123",
    "2024-08-15T00:00:00Z,Rust/RUSTSEC-2021-124",
    "2024-08-15T00:00:00Z,PyPI/PYSEC-2021-123",
    "2024-08-15T00:00:00Z,PyPI/PYSEC-2021-124",
  ]

  let files = [
    first_file_content,
    second_file_content,
    third_file_content,
    latest_file_content,
  ]

  let expected_result = [
    "2024-08-15T00:00:00Z,Ruby/RUBYSEC-2021-123",
    "2024-08-15T00:00:00Z,Ruby/RUBYSEC-2021-124",
  ]

  let actual_result = vuln_diff_extractors(files)

  assert expected_result == actual_result
}
