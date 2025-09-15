import collectors/actual_vulnerability_collector.{
  type Event, type OSVVulnerability, type Range,
}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import index_searcher/models.{type VulnIndex, get_table_ref}

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
          let version_count = case affected_pkg.package, affected_pkg.versions {
            Some(package), Some(versions) ->
              list.fold(versions, 0, fn(ver_acc, version) {
                // ETSテーブルに (正規化キー, 脆弱性ID) を挿入
                insert_vulnerability(
                  index,
                  package.ecosystem,
                  package.name,
                  version,
                  vulnerability.id,
                )
                ver_acc + 1
              })
            _, _ -> 0
          }

          // ranges フィールドの処理を実装
          let range_count = case affected_pkg.package, affected_pkg.ranges {
            Some(package), Some(ranges) ->
              process_vulnerability_ranges(
                index,
                ranges,
                package.ecosystem,
                package.name,
                vulnerability.id,
              )
            _, _ -> 0
          }

          pkg_acc + version_count + range_count
        })

      acc + vuln_count
    })

  Ok(total_count)
}

// ETS操作の外部関数
import gleam/erlang/atom

@external(erlang, "ets", "insert")
fn ets_insert(table: atom.Atom, tuple: #(String, String)) -> Bool

// 正規化関数
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

// ranges フィールドを処理する関数
fn process_vulnerability_ranges(
  index: VulnIndex,
  ranges: List(Range),
  ecosystem: String,
  name: String,
  vuln_id: String,
) -> Int {
  list.fold(ranges, 0, fn(acc, range) {
    case range.range_type {
      "SEMVER" -> process_semver_range(index, range, ecosystem, name, vuln_id)
      "ECOSYSTEM" ->
        process_ecosystem_range(index, range, ecosystem, name, vuln_id)
      _ -> 0
      // 未対応のrange_type
    }
    + acc
  })
}

// SEMVER範囲を処理する関数
fn process_semver_range(
  index: VulnIndex,
  range: Range,
  ecosystem: String,
  name: String,
  vuln_id: String,
) -> Int {
  // イベントから範囲を抽出
  case extract_range_from_events(range.events) {
    Some(#(introduced, fixed)) -> {
      // 範囲に基づいて脆弱性情報をETSに保存
      // 現在は簡易実装として、範囲情報を特別なキーで保存
      let range_key = create_range_key(ecosystem, name, introduced, fixed)
      ets_insert(get_table_ref(index), #(range_key, vuln_id))
      1
    }
    None -> 0
  }
}

// ECOSYSTEM範囲を処理する関数（現在は簡易実装）
fn process_ecosystem_range(
  index: VulnIndex,
  range: Range,
  ecosystem: String,
  name: String,
  vuln_id: String,
) -> Int {
  // ECOSYSTEM範囲の処理は複雑なため、現在は基本的な処理のみ
  case extract_range_from_events(range.events) {
    Some(#(introduced, fixed)) -> {
      let range_key = create_range_key(ecosystem, name, introduced, fixed)
      ets_insert(get_table_ref(index), #(range_key, vuln_id))
      1
    }
    None -> 0
  }
}

// イベントリストから範囲を抽出
fn extract_range_from_events(events: List(Event)) -> Option(#(String, String)) {
  let introduced = find_introduced_version(events)
  let fixed = find_fixed_version(events)

  case introduced, fixed {
    Some(intro), Some(fix) -> Some(#(intro, fix))
    Some(intro), None -> Some(#(intro, "999.999.999"))
    // 固定されていない場合
    None, Some(fix) -> Some(#("0", fix))
    // 0から固定バージョンまで
    None, None -> None
  }
}

// introduced イベントを検索
fn find_introduced_version(events: List(Event)) -> Option(String) {
  case events {
    [] -> None
    [event, ..rest] ->
      case event.introduced {
        Some(version) -> Some(version)
        None -> find_introduced_version(rest)
      }
  }
}

// fixed イベントを検索
fn find_fixed_version(events: List(Event)) -> Option(String) {
  case events {
    [] -> None
    [event, ..rest] ->
      case event.fixed {
        Some(version) -> Some(version)
        None -> find_fixed_version(rest)
      }
  }
}

// 範囲キーを作成（特別なプレフィックスを使用）
fn create_range_key(
  ecosystem: String,
  name: String,
  introduced: String,
  fixed: String,
) -> String {
  let norm_eco = string.lowercase(ecosystem)
  let norm_name = normalize_package_name(norm_eco, name)
  "range:" <> norm_eco <> ":" <> norm_name <> ":" <> introduced <> ":" <> fixed
}

fn insert_vulnerability(
  index: VulnIndex,
  ecosystem: String,
  name: String,
  version: String,
  vuln_id: String,
) -> Nil {
  let key = normalize_package_key(ecosystem, name, version)
  ets_insert(get_table_ref(index), #(key, vuln_id))
  Nil
}
