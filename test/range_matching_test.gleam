import collectors/actual_vulnerability_collector.{
  AffectedPackage, Event, OSVPackage, OSVVulnerability, Range,
}
import gleam/option.{None, Some}
import gleeunit
import gleeunit/should
import index_searcher/searcher
import index_searcher/vuln_index_loader

pub fn main() {
  gleeunit.main()
}

// 範囲マッチングの基本テスト
pub fn range_matching_basic_test() {
  // 実際のOSV脆弱性データを模擬（任意のパッケージとバージョン範囲）
  let vuln =
    OSVVulnerability(
      id: "TEST-RANGE-001",
      published: "2023-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      references: [],
      affected: [
        AffectedPackage(
          package: Some(OSVPackage(ecosystem: "npm", name: "test-package")),
          versions: None,
          ranges: Some([
            Range("SEMVER", [
              Event(Some("0"), None),
              // introduced: "0"
              Event(None, Some("1.5.0")),
              // fixed: "1.5.0"
            ]),
          ]),
        ),
      ],
    )

  // インデックスを構築
  let index = searcher.create_vuln_index()
  let assert Ok(count) =
    vuln_index_loader.build_index_from_target_vulnerabilities(index, [vuln])

  // インデックスに脆弱性が登録されることを確認
  count |> should.equal(1)

  // 範囲内のバージョン（1.2.0）で脆弱性が検出されることを確認
  let result_vulnerable =
    searcher.lookup_vulnerability(index, "npm", "test-package", "1.2.0")

  case result_vulnerable {
    Some(vuln_id) -> vuln_id |> should.equal("TEST-RANGE-001")
    None -> should.fail()
  }

  // 範囲外のバージョン（1.5.0以上）で脆弱性が検出されないことを確認
  let result_safe =
    searcher.lookup_vulnerability(index, "npm", "test-package", "1.5.0")

  result_safe |> should.equal(None)
}

// 複数の範囲パターンをテスト
pub fn multiple_range_patterns_test() {
  let vulnerabilities = [
    // パターン1: 0から2.0.0未満
    OSVVulnerability(
      id: "TEST-RANGE-002",
      published: "2023-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      references: [],
      affected: [
        AffectedPackage(
          package: Some(OSVPackage(ecosystem: "npm", name: "package-a")),
          versions: None,
          ranges: Some([
            Range("SEMVER", [
              Event(Some("0"), None),
              Event(None, Some("2.0.0")),
            ]),
          ]),
        ),
      ],
    ),
    // パターン2: 1.0.0から3.0.0未満
    OSVVulnerability(
      id: "TEST-RANGE-003",
      published: "2023-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      references: [],
      affected: [
        AffectedPackage(
          package: Some(OSVPackage(ecosystem: "npm", name: "package-b")),
          versions: None,
          ranges: Some([
            Range("SEMVER", [
              Event(Some("1.0.0"), None),
              Event(None, Some("3.0.0")),
            ]),
          ]),
        ),
      ],
    ),
  ]

  let index = searcher.create_vuln_index()
  let assert Ok(count) =
    vuln_index_loader.build_index_from_target_vulnerabilities(
      index,
      vulnerabilities,
    )

  count |> should.equal(2)

  // package-a@1.5.0 は TEST-RANGE-002 にマッチするはず
  let result_a =
    searcher.lookup_vulnerability(index, "npm", "package-a", "1.5.0")
  case result_a {
    Some(vuln_id) -> vuln_id |> should.equal("TEST-RANGE-002")
    None -> should.fail()
  }

  // package-b@2.0.0 は TEST-RANGE-003 にマッチするはず
  let result_b =
    searcher.lookup_vulnerability(index, "npm", "package-b", "2.0.0")
  case result_b {
    Some(vuln_id) -> vuln_id |> should.equal("TEST-RANGE-003")
    None -> should.fail()
  }

  // package-a@2.0.0 は範囲外なのでマッチしないはず
  let result_safe =
    searcher.lookup_vulnerability(index, "npm", "package-a", "2.0.0")
  result_safe |> should.equal(None)
}
