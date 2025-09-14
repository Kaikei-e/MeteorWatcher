import gleam/dict
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import index_searcher/models.{type Package, Package}
import simplifile

// ===== ロックファイル解析 =====

pub type LockFileType {
  CargoLock
  GoMod
  GoSum
  PackageLockJson
  YarnLock
  PnpmLock
}

pub fn detect_lockfile_type(filename: String) -> Option(LockFileType) {
  case filename {
    "Cargo.lock" -> Some(CargoLock)
    "go.mod" -> Some(GoMod)
    "go.sum" -> Some(GoSum)
    "package-lock.json" -> Some(PackageLockJson)
    "yarn.lock" -> Some(YarnLock)
    "pnpm-lock.yaml" -> Some(PnpmLock)
    _ -> None
  }
}

pub fn parse_lockfile(
  file_path: String,
  lockfile_type: LockFileType,
) -> Result(List(Package), String) {
  case simplifile.read(file_path) {
    Ok(content) -> {
      case lockfile_type {
        CargoLock -> parse_cargo_lock(content)
        GoMod -> parse_go_mod(content)
        GoSum -> parse_go_sum(content)
        PackageLockJson -> parse_package_lock_json(content)
        _ -> Error("Unsupported lockfile type")
      }
    }
    Error(_) -> Error("Failed to read file")
  }
}

// ===== Cargo.lock パーサー =====

fn parse_cargo_lock(content: String) -> Result(List(Package), String) {
  let lines = string.split(content, "\n")
  parse_cargo_lock_lines(lines, [], None, None)
}

fn parse_cargo_lock_lines(
  lines: List(String),
  packages: List(Package),
  current_name: Option(String),
  current_version: Option(String),
) -> Result(List(Package), String) {
  case lines {
    [] -> Ok(packages)
    [line, ..rest] -> {
      let trimmed = string.trim(line)

      // [[package]] セクションの検出
      case string.starts_with(trimmed, "[[package]]") {
        True -> parse_cargo_lock_lines(rest, packages, None, None)
        False -> {
          // name = "package_name" の解析
          case string.starts_with(trimmed, "name = \"") {
            True -> {
              let name = extract_quoted_value(trimmed, "name = \"")
              parse_cargo_lock_lines(
                rest,
                packages,
                Some(name),
                current_version,
              )
            }
            False -> {
              // version = "1.0.0" の解析
              case string.starts_with(trimmed, "version = \"") {
                True -> {
                  let version = extract_quoted_value(trimmed, "version = \"")
                  case current_name {
                    Some(name) -> {
                      let package = Package("cargo", name, version)
                      parse_cargo_lock_lines(
                        rest,
                        [package, ..packages],
                        None,
                        None,
                      )
                    }
                    None ->
                      parse_cargo_lock_lines(
                        rest,
                        packages,
                        None,
                        Some(version),
                      )
                  }
                }
                False ->
                  parse_cargo_lock_lines(
                    rest,
                    packages,
                    current_name,
                    current_version,
                  )
              }
            }
          }
        }
      }
    }
  }
}

fn extract_quoted_value(line: String, prefix: String) -> String {
  line
  |> string.drop_start(string.length(prefix))
  |> string.drop_end(1)
  // 末尾の " を削除
}

// ===== go.mod パーサー =====

fn parse_go_mod(content: String) -> Result(List(Package), String) {
  let lines = string.split(content, "\n")
  parse_go_mod_lines(lines, [])
}

fn parse_go_mod_lines(
  lines: List(String),
  packages: List(Package),
) -> Result(List(Package), String) {
  case lines {
    [] -> Ok(packages)
    [line, ..rest] -> {
      let trimmed = string.trim(line)

      // require行の解析: require module.name v1.2.3
      case string.starts_with(trimmed, "require ") {
        True -> {
          case parse_go_require_line(trimmed) {
            Some(package) -> parse_go_mod_lines(rest, [package, ..packages])
            None -> parse_go_mod_lines(rest, packages)
          }
        }
        False -> parse_go_mod_lines(rest, packages)
      }
    }
  }
}

fn parse_go_require_line(line: String) -> Option(Package) {
  // "require module.name v1.2.3" を解析
  let parts = string.split(string.trim(line), " ")
  case parts {
    ["require", module_name, version] ->
      Some(Package("go", module_name, version))
    _ -> None
  }
}

// ===== go.sum パーサー =====

fn parse_go_sum(content: String) -> Result(List(Package), String) {
  let lines = string.split(content, "\n")
  parse_go_sum_lines(lines, [])
}

fn parse_go_sum_lines(
  lines: List(String),
  packages: List(Package),
) -> Result(List(Package), String) {
  case lines {
    [] -> Ok(list.unique(packages))
    // 重複削除
    [line, ..rest] -> {
      let trimmed = string.trim(line)

      // go.sum行の解析: module.name v1.2.3 h1:hash
      case parse_go_sum_line(trimmed) {
        Some(package) -> parse_go_sum_lines(rest, [package, ..packages])
        None -> parse_go_sum_lines(rest, packages)
      }
    }
  }
}

fn parse_go_sum_line(line: String) -> Option(Package) {
  let parts = string.split(line, " ")
  case parts {
    [module_name, version, _hash] ->
      // /go.mod サフィックスは除去
      case string.ends_with(version, "/go.mod") {
        True -> None
        False -> Some(Package("go", module_name, version))
      }
    _ -> None
  }
}

// ===== package-lock.json パーサー =====

fn parse_package_lock_json(content: String) -> Result(List(Package), String) {
  case json.parse(content, decode_package_lock()) {
    Ok(packages) -> Ok(packages)
    Error(_) -> Error("Failed to parse package-lock.json")
  }
}

// package-lock.jsonの構造をデコード
fn decode_package_lock() {
  use packages <- decode.field(
    "packages",
    decode.dict(decode.string, decode_package_entry()),
  )

  // "packages"フィールドから全てのパッケージエントリを取得
  let package_list =
    packages
    |> dict.to_list()
    |> list.filter_map(fn(entry) {
      let #(path, package_data) = entry
      case extract_package_from_path(path, package_data) {
        Some(package) -> Ok(package)
        None -> Error(Nil)
      }
    })

  decode.success(package_list)
}

// パッケージエントリをデコード
fn decode_package_entry() {
  use version <- decode.field("version", decode.optional(decode.string))
  decode.success(version)
}

// パッケージパスからパッケージ情報を抽出
fn extract_package_from_path(
  path: String,
  version_opt: Option(String),
) -> Option(Package) {
  case version_opt {
    None -> None
    Some(version) -> {
      case string.starts_with(path, "node_modules/") {
        True -> {
          // "node_modules/" プレフィックスを削除
          let package_name = string.drop_start(path, 13)
          // ネストしたnode_modulesは除外 (例: node_modules/foo/node_modules/bar)
          case string.contains(package_name, "/node_modules/") {
            True -> None
            False -> Some(Package("npm", package_name, version))
          }
        }
        False -> None
      }
    }
  }
}
