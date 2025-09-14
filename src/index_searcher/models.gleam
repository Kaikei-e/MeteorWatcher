import gleam/erlang/atom

// ETSテーブル用の型
pub opaque type VulnIndex {
  VulnIndex(table_ref: atom.Atom)
}

// VulnIndexのコンストラクタ関数
pub fn new_vuln_index(table_ref: atom.Atom) -> VulnIndex {
  VulnIndex(table_ref)
}

// VulnIndexからtable_refを取得する関数
pub fn get_table_ref(index: VulnIndex) -> atom.Atom {
  let VulnIndex(table_ref) = index
  table_ref
}

// パッケージ情報
pub type Package {
  Package(ecosystem: String, name: String, version: String)
}

// 脆弱性マッチ結果
pub type VulnMatch {
  VulnMatch(package: Package, vuln_id: String, file_path: String)
}

// OSVデータの構造（簡略版）
pub type OSVVuln {
  OSVVuln(id: String, affected: List(AffectedPackage))
}

pub type AffectedPackage {
  AffectedPackage(
    package: OSVPackage,
    versions: List(String),
    ranges: List(Range),
  )
}

pub type Range {
  Range(range_type: String, repo: String, events: List(Event))
}

pub type Event {
  Event(introduced: String, fixed: String)
}

pub type OSVPackage {
  OSVPackage(ecosystem: String, name: String)
}
