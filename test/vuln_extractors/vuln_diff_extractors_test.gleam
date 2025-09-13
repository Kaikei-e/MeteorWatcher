import vuln_extractors/vuln_diff_extractors.{vuln_diff_extractors}

pub fn vuln_diff_extractors_test() {
  let first_file_content = [
    "PyPI/PYSEC-2021-123",
    "PyPI/PYSEC-2021-124",
  ]
  let second_file_content = [
    "Go/GOSEC-2021-123",
    "Go/GOSEC-2021-124",
    "PyPI/PYSEC-2021-123",
    "PyPI/PYSEC-2021-124",
  ]
  let third_file_content = [
    "Rust/RUSTSEC-2021-123",
    "Rust/RUSTSEC-2021-124",
    "Go/GOSEC-2021-123",
    "Go/GOSEC-2021-124",
    "PyPI/PYSEC-2021-123",
    "PyPI/PYSEC-2021-124",
  ]
  let latest_file_content = [
    "Ruby/RUBYSEC-2021-123",
    "Ruby/RUBYSEC-2021-124",
    "Go/GOSEC-2021-123",
    "Go/GOSEC-2021-124",
    "Rust/RUSTSEC-2021-123",
    "Rust/RUSTSEC-2021-124",
    "PyPI/PYSEC-2021-123",
    "PyPI/PYSEC-2021-124",
  ]

  let files = [
    first_file_content,
    second_file_content,
    third_file_content,
    latest_file_content,
  ]

  let expected_result = [
    "Ruby/RUBYSEC-2021-123",
    "Ruby/RUBYSEC-2021-124",
  ]

  let actual_result = vuln_diff_extractors(files)

  assert expected_result == actual_result
}
