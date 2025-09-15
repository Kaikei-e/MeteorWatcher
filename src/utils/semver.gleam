// SemVer バージョン比較ユーティリティ
// 簡単な実装（完全なSemVer仕様ではなく、基本的な比較のみ）

import gleam/int
import gleam/order
import gleam/string

pub type Version {
  Version(major: Int, minor: Int, patch: Int)
}

// バージョン文字列をパースしてVersion型に変換
pub fn parse_version(version_str: String) -> Result(Version, String) {
  let cleaned =
    version_str
    |> string.trim()
    |> string.drop_start(case string.starts_with(version_str, "v") {
      True -> 1
      False -> 0
    })

  case string.split(cleaned, ".") {
    [major_str, minor_str, patch_str] -> {
      case int.parse(major_str), int.parse(minor_str), int.parse(patch_str) {
        Ok(major), Ok(minor), Ok(patch) -> Ok(Version(major, minor, patch))
        _, _, _ -> Error("Invalid version format")
      }
    }
    [major_str, minor_str] -> {
      case int.parse(major_str), int.parse(minor_str) {
        Ok(major), Ok(minor) -> Ok(Version(major, minor, 0))
        _, _ -> Error("Invalid version format")
      }
    }
    [major_str] -> {
      case int.parse(major_str) {
        Ok(major) -> Ok(Version(major, 0, 0))
        _ -> Error("Invalid version format")
      }
    }
    _ -> Error("Invalid version format")
  }
}

// バージョンの比較
pub fn compare_versions(v1: Version, v2: Version) -> order.Order {
  case int.compare(v1.major, v2.major) {
    order.Eq ->
      case int.compare(v1.minor, v2.minor) {
        order.Eq -> int.compare(v1.patch, v2.patch)
        result -> result
      }
    result -> result
  }
}

// バージョンがある範囲に含まれるかチェック
pub fn version_in_range(
  version: String,
  introduced: String,
  fixed: String,
) -> Bool {
  case parse_version(version), parse_version(introduced), parse_version(fixed) {
    Ok(v), Ok(intro), Ok(fix) -> {
      let after_introduced = case compare_versions(v, intro) {
        order.Gt | order.Eq -> True
        order.Lt -> False
      }
      let before_fixed = case compare_versions(v, fix) {
        order.Lt -> True
        order.Gt | order.Eq -> False
      }
      after_introduced && before_fixed
    }
    _, _, _ -> False
  }
}

// "0" から指定されたバージョンまでの範囲をチェック
pub fn version_in_range_from_zero(version: String, fixed: String) -> Bool {
  case parse_version(version), parse_version(fixed) {
    Ok(v), Ok(fix) ->
      case compare_versions(v, fix) {
        order.Lt -> True
        order.Gt | order.Eq -> False
      }
    _, _ -> False
  }
}

// バージョンが指定されたバージョン以降かチェック
pub fn version_gte(version: String, introduced: String) -> Bool {
  case parse_version(version), parse_version(introduced) {
    Ok(v), Ok(intro) ->
      case compare_versions(v, intro) {
        order.Gt | order.Eq -> True
        order.Lt -> False
      }
    _, _ -> False
  }
}

// OSV形式の範囲指定（>=0 <2.4.12など）をサポート
pub fn satisfies_range(version: String, range_spec: String) -> Bool {
  // 簡易実装：>=0 <X.X.X 形式をパース
  case string.contains(range_spec, ">=0") && string.contains(range_spec, "<") {
    True -> {
      // "<" の後のバージョンを抽出
      let parts = string.split(range_spec, "<")
      case parts {
        [_, fixed_part] -> {
          let fixed = string.trim(fixed_part)
          version_in_range_from_zero(version, fixed)
        }
        _ -> False
      }
    }
    False -> {
      // その他の範囲形式（将来の拡張用）
      False
    }
  }
}
