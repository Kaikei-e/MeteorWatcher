import gleam/erlang/atom
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import index_searcher/models.{
  type VulnIndex, type VulnMatch, VulnMatch, get_table_ref, new_vuln_index,
}
import index_searcher/parser.{detect_lockfile_type, parse_lockfile}
import simplifile

@external(erlang, "erlang", "binary_to_list")
fn binary_to_list(binary: String) -> List(Int)

@external(erlang, "erlang", "list_to_atom")
fn list_to_atom(chars: List(Int)) -> atom.Atom

@external(erlang, "ets", "new")
fn ets_new(name: atom.Atom, options: List(atom.Atom)) -> atom.Atom

@external(erlang, "ets", "insert")
fn ets_insert(table: atom.Atom, tuple: #(String, String)) -> Bool

@external(erlang, "ets", "lookup")
fn ets_lookup(table: atom.Atom, key: String) -> List(#(String, String))

pub fn create_vuln_index() -> VulnIndex {
  let name = list_to_atom(binary_to_list("vuln_index"))
  let opt_set = list_to_atom(binary_to_list("set"))
  let opt_named_table = list_to_atom(binary_to_list("named_table"))
  // read_concurrencyオプションを削除してシンプルにする
  let table = ets_new(name, [opt_named_table, opt_set])
  new_vuln_index(table)
}

pub fn insert_vulnerability(
  index: VulnIndex,
  ecosystem: String,
  name: String,
  version: String,
  vuln_id: String,
) -> Nil {
  let key = normalize_package_key(ecosystem, name, version)
  let table_ref = get_table_ref(index)
  ets_insert(table_ref, #(key, vuln_id))
  Nil
}

pub fn lookup_vulnerability(
  index: VulnIndex,
  ecosystem: String,
  name: String,
  version: String,
) -> Option(String) {
  let key = normalize_package_key(ecosystem, name, version)
  let table_ref = get_table_ref(index)
  case ets_lookup(table_ref, key) {
    [#(_, vuln_id), ..] -> Some(vuln_id)
    [] -> None
  }
}

// ===== 正規化関数 =====

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
    // npmはcase-sensitive実際はcase-insensitive扱い
    "pypi" -> string.lowercase(string.replace(name, "_", "-"))
    // PEP 503
    "cargo" -> string.lowercase(name)
    // cargo crate名は小文字
    "go" -> name
    // Go module名は大文字小文字区別
    _ -> string.lowercase(name)
  }
}

fn normalize_version(version: String) -> String {
  let trimmed = string.trim(version)
  case string.starts_with(trimmed, "v") {
    True -> string.drop_start(trimmed, 1)
    False -> trimmed
  }
}

// ===== 並列スキャン =====

pub fn scan_directory_sequential(
  index: VulnIndex,
  root_dir: String,
) -> Result(List(VulnMatch), String) {
  use lockfiles <- result.try(find_lockfiles(root_dir))

  // ファイル単位で順次処理
  let matches =
    list.fold(lockfiles, [], fn(acc, file_path) {
      case scan_single_file(index, file_path) {
        Ok(file_matches) -> list.append(acc, file_matches)
        Error(_) -> acc
      }
    })

  Ok(matches)
}

fn find_lockfiles(dir: String) -> Result(List(String), String) {
  find_lockfiles_recursive(dir, [])
}

fn find_lockfiles_recursive(
  dir: String,
  acc: List(String),
) -> Result(List(String), String) {
  case simplifile.read_directory(dir) {
    Ok(entries) -> {
      list.fold(entries, Ok(acc), fn(acc_result, entry) {
        use current_acc <- result.try(acc_result)
        let full_path = dir <> "/" <> entry

        case simplifile.is_directory(full_path) {
          Ok(True) -> find_lockfiles_recursive(full_path, current_acc)
          Ok(False) -> {
            case detect_lockfile_type(entry) {
              Some(_) -> Ok([full_path, ..current_acc])
              None -> Ok(current_acc)
            }
          }
          Error(_) -> Ok(current_acc)
        }
      })
    }
    Error(_) -> Error("Failed to read directory")
  }
}

fn scan_single_file(
  index: VulnIndex,
  file_path: String,
) -> Result(List(VulnMatch), String) {
  let filename = case list.reverse(string.split(file_path, "/")) {
    [last, ..] -> last
    [] -> file_path
  }

  use lockfile_type <- result.try(case detect_lockfile_type(filename) {
    Some(t) -> Ok(t)
    None -> Error("Unknown lockfile type")
  })

  use packages <- result.try(parse_lockfile(file_path, lockfile_type))

  let matches =
    list.filter_map(packages, fn(package) {
      case
        lookup_vulnerability(
          index,
          package.ecosystem,
          package.name,
          package.version,
        )
      {
        Some(vuln_id) -> Ok(VulnMatch(package, vuln_id, file_path))
        None -> Error(Nil)
      }
    })

  Ok(matches)
}
