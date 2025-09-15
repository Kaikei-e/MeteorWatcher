import collectors/actual_vulnerability_collector.{
  AffectedPackage, Event, OSVPackage, OSVVulnerability, Range,
}
import gleam/list
import gleam/option.{None, Some}
import gleeunit
import gleeunit/should
import index_searcher/searcher
import index_searcher/vuln_index_loader
import utils/semver

pub fn main() {
  gleeunit.main()
}

// 実際のcipher-base脆弱性でテスト
pub fn cipher_base_version_comparison_test() {
  // 実際のOSVデータから: GHSA-cpq7-6gpm-g9rc, cipher-base, 0 < 1.0.5
  let vuln =
    OSVVulnerability(
      id: "GHSA-cpq7-6gpm-g9rc",
      published: "2025-08-21T14:47:35Z",
      modified: "2025-09-13T04:46:43Z",
      references: [],
      affected: [
        AffectedPackage(
          package: Some(OSVPackage(ecosystem: "npm", name: "cipher-base")),
          versions: None,
          ranges: Some([
            Range("SEMVER", [
              Event(Some("0"), None),
              // introduced: "0"
              Event(None, Some("1.0.5")),
              // fixed: "1.0.5"
            ]),
          ]),
        ),
      ],
    )

  // インデックスを構築
  let index = searcher.create_vuln_index()
  let assert Ok(count) =
    vuln_index_loader.build_index_from_target_vulnerabilities(index, [vuln])

  count |> should.equal(1)

  // 脆弱性のあるバージョンをテスト
  let vulnerable_versions = ["1.0.0", "1.0.4", "0.5.0"]
  vulnerable_versions
  |> list.each(fn(version) {
    let result =
      searcher.lookup_vulnerability(index, "npm", "cipher-base", version)
    case result {
      Some(vuln_id) -> vuln_id |> should.equal("GHSA-cpq7-6gpm-g9rc")
      None -> should.fail()
    }
  })

  // 安全なバージョンをテスト
  let safe_versions = ["1.0.5", "1.1.0", "2.0.0"]
  safe_versions
  |> list.each(fn(version) {
    let result =
      searcher.lookup_vulnerability(index, "npm", "cipher-base", version)
    result |> should.equal(None)
  })
}

// semverモジュールの直接テスト
pub fn semver_version_in_range_test() {
  // cipher-baseの範囲: 0 <= version < 1.0.5
  semver.version_in_range("1.0.0", "0", "1.0.5") |> should.be_true()
  semver.version_in_range("1.0.4", "0", "1.0.5") |> should.be_true()
  semver.version_in_range("0.5.0", "0", "1.0.5") |> should.be_true()

  // 境界値テスト
  semver.version_in_range("0", "0", "1.0.5") |> should.be_true()
  // inclusive introduced
  semver.version_in_range("1.0.5", "0", "1.0.5") |> should.be_false()
  // exclusive fixed

  // 範囲外
  semver.version_in_range("1.0.5", "0", "1.0.5") |> should.be_false()
  semver.version_in_range("1.1.0", "0", "1.0.5") |> should.be_false()
  semver.version_in_range("2.0.0", "0", "1.0.5") |> should.be_false()
}

// prebid-universal-creative（完全一致）のテスト
pub fn prebid_exact_version_test() {
  // 実際のOSVデータから: MAL-2025-47027, prebid-universal-creative, 1.17.3
  let vuln =
    OSVVulnerability(
      id: "MAL-2025-47027",
      published: "2025-09-11T03:58:52Z",
      modified: "2025-09-11T03:58:52Z",
      references: [],
      affected: [
        AffectedPackage(
          package: Some(OSVPackage(
            ecosystem: "npm",
            name: "prebid-universal-creative",
          )),
          versions: Some(["1.17.3"]),
          ranges: None,
        ),
      ],
    )

  let index = searcher.create_vuln_index()
  let assert Ok(count) =
    vuln_index_loader.build_index_from_target_vulnerabilities(index, [vuln])

  count |> should.equal(1)

  // 完全一致のテスト
  let result =
    searcher.lookup_vulnerability(
      index,
      "npm",
      "prebid-universal-creative",
      "1.17.3",
    )
  case result {
    Some(vuln_id) -> vuln_id |> should.equal("MAL-2025-47027")
    None -> should.fail()
  }

  // 異なるバージョンは検出されないはず
  let safe_result =
    searcher.lookup_vulnerability(
      index,
      "npm",
      "prebid-universal-creative",
      "1.17.2",
    )
  safe_result |> should.equal(None)
}
