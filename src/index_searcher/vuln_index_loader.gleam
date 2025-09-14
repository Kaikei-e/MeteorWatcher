import collectors/actual_vulnerability_collector.{type OSVVulnerability}
import gleam/list
import gleam/string
import index_searcher/models.{type VulnIndex}

pub fn build_index_from_target_vulnerabilities(
  index: VulnIndex,
  target_vulnerabilities: List(OSVVulnerability),
) -> Result(Int, String) {
  // 3つのネストしたfoldで全ての(ecosystem, name, version) -> vuln_id マッピングを作成
  let total_count =
    list.fold(target_vulnerabilities, 0, fn(acc, vulnerability) {
      // 各脆弱性の影響パッケージを処理
      let vuln_count =
        list.fold(vulnerability.affected, 0, fn(pkg_acc, affected_pkg) {
          // 現在は versions のみ処理（完全一致）
          let version_count =
            list.fold(affected_pkg.versions, 0, fn(ver_acc, version) {
              // ETSテーブルに (正規化キー, 脆弱性ID) を挿入
              insert_vulnerability(
                index,
                affected_pkg.package.ecosystem,
                affected_pkg.package.name,
                version,
                vulnerability.id,
              )
              ver_acc + 1
            })

          // TODO: 将来実装 - ranges フィールドの処理
          // SemVer範囲（">=1.0.0, <2.0.0" 等）を展開してバージョンリストに変換
          // let range_count = process_vulnerability_ranges(
          //   index,
          //   affected_pkg.ranges,
          //   affected_pkg.package.ecosystem,
          //   affected_pkg.package.name,
          //   vulnerability.id
          // )

          pkg_acc + version_count
        })

      acc + vuln_count
    })

  Ok(total_count)
}

// ETS操作の外部関数（既存実装から）
@external(erlang, "ets", "insert")
fn ets_insert(table: String, tuple: #(String, String)) -> Bool

// 正規化関数（既存実装から）
fn normalize_package_key(
  ecosystem: String,
  name: String,
  version: String,
) -> String {
  let norm_eco = string.lowercase(ecosystem)
  let norm_name = normalize_package_name(norm_eco, name)
  let norm_ver = normalize_version(version)
  norm_eco <> ":" <> norm_name <> ":" <> norm_ver
}

fn normalize_package_name(ecosystem: String, name: String) -> String {
  case ecosystem {
    "npm" -> string.lowercase(name)
    "pypi" -> string.lowercase(string.replace(name, "_", "-"))
    "cargo" -> string.lowercase(name)
    "go" -> name
    _ -> string.lowercase(name)
  }
}

fn normalize_version(version: String) -> String {
  version
  |> string.trim
  |> string.drop_start(case string.starts_with(version, "v") {
    True -> 1
    False -> 0
  })
}

fn insert_vulnerability(
  index: VulnIndex,
  ecosystem: String,
  name: String,
  version: String,
  vuln_id: String,
) -> Nil {
  let key = normalize_package_key(ecosystem, name, version)
  ets_insert(models.get_table_ref(index), #(key, vuln_id))
  Nil
}