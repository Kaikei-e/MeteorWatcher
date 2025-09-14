import gleam/list
import gleam/string
import vuln_extractors/vuln_diff_extractors.{vuln_diff_extractors}

pub fn vuln_diff_extractors_test() {
  // テストケース1: 各ファイルにのみ存在し、他のファイルには存在しない脆弱性IDを抽出
  let file1 = [
    "PyPI/PYSEC-2021-123",
    // 複数ファイルに存在
    "PyPI/PYSEC-2021-124",
    // 複数ファイルに存在
    "File1/UNIQUE-001",
    // file1のみに存在
  ]
  let file2 = [
    "Go/GOSEC-2021-123",
    // 複数ファイルに存在
    "Go/GOSEC-2021-124",
    // 複数ファイルに存在
    "PyPI/PYSEC-2021-123",
    // 複数ファイルに存在
    "PyPI/PYSEC-2021-124",
    // 複数ファイルに存在
    "File2/UNIQUE-002",
    // file2のみに存在
  ]
  let file3 = [
    "Rust/RUSTSEC-2021-123",
    // 複数ファイルに存在
    "Rust/RUSTSEC-2021-124",
    // 複数ファイルに存在
    "Go/GOSEC-2021-123",
    // 複数ファイルに存在
    "Go/GOSEC-2021-124",
    // 複数ファイルに存在
    "PyPI/PYSEC-2021-123",
    // 複数ファイルに存在
    "PyPI/PYSEC-2021-124",
    // 複数ファイルに存在
    "File3/UNIQUE-003",
    // file3のみに存在
  ]
  let file4 = [
    "Ruby/RUBYSEC-2021-123",
    // file4のみに存在
    "Ruby/RUBYSEC-2021-124",
    // file4のみに存在
    "Go/GOSEC-2021-123",
    // 複数ファイルに存在
    "Go/GOSEC-2021-124",
    // 複数ファイルに存在
    "Rust/RUSTSEC-2021-123",
    // 複数ファイルに存在
    "Rust/RUSTSEC-2021-124",
    // 複数ファイルに存在
    "PyPI/PYSEC-2021-123",
    // 複数ファイルに存在
    "PyPI/PYSEC-2021-124",
    // 複数ファイルに存在
  ]

  let files = [file1, file2, file3, file4]

  // 各ファイルにのみ存在する脆弱性ID（出現頻度が1のもの）を抽出
  let expected_result_sorted =
    list.sort(
      [
        "File1/UNIQUE-001",
        "File2/UNIQUE-002",
        "File3/UNIQUE-003",
        "Ruby/RUBYSEC-2021-123",
        "Ruby/RUBYSEC-2021-124",
      ],
      by: string.compare,
    )

  let actual_result = vuln_diff_extractors(files)
  let actual_result_sorted = list.sort(actual_result, by: string.compare)

  assert expected_result_sorted == actual_result_sorted
}

pub fn vuln_diff_extractors_three_files_test() {
  // テストケース2: 3つのファイルの場合、各ファイルにのみ存在するIDを抽出
  let file1 = ["CVE-2021-001", "CVE-2021-002"]
  // CVE-2021-001はfile1のみ
  let file2 = ["CVE-2021-002", "CVE-2021-003"]
  // CVE-2021-003はfile2のみ
  let file3 = ["CVE-2021-003", "CVE-2021-004", "CVE-2021-005"]
  // CVE-2021-004, CVE-2021-005はfile3のみ

  let files = [file1, file2, file3]

  // 各ファイルにのみ存在する脆弱性ID（出現頻度が1のもの）を抽出
  // CVE-2021-001 (file1のみ), CVE-2021-004, CVE-2021-005 (file3のみ)
  // CVE-2021-002は file1とfile2に存在、CVE-2021-003は file2とfile3に存在するため除外
  let expected_result_sorted =
    list.sort(
      [
        "CVE-2021-001",
        "CVE-2021-004",
        "CVE-2021-005",
      ],
      by: string.compare,
    )

  let actual_result = vuln_diff_extractors(files)
  let actual_result_sorted = list.sort(actual_result, by: string.compare)

  assert expected_result_sorted == actual_result_sorted
}

pub fn vuln_diff_extractors_empty_test() {
  // テストケース3: 空のリストの場合
  let files = []
  let expected_result = []
  let actual_result = vuln_diff_extractors(files)
  assert expected_result == actual_result
}

pub fn vuln_diff_extractors_single_file_test() {
  // テストケース4: 1つのファイルの場合
  let files = [["CVE-2021-001", "CVE-2021-002"]]
  let expected_result_sorted =
    list.sort(
      [
        "CVE-2021-001",
        "CVE-2021-002",
      ],
      by: string.compare,
    )

  let actual_result = vuln_diff_extractors(files)
  let actual_result_sorted = list.sort(actual_result, by: string.compare)

  assert expected_result_sorted == actual_result_sorted
}
