import gleam/list
import gleam/set

// ファイルの中身を文字列として受け取る
// Diffで新しいものを抽出
// ファイルの中身は積み上げ形式

pub fn vuln_diff_extractors(
  vulnerabilities_list: List(List(String)),
) -> List(String) {
  case list.reverse(vulnerabilities_list) {
    [] -> []
    [latest, ..prev_rev] ->
      // 最新にあり、過去に一度もないものだけ残す
      list.filter(latest, fn(line) {
        !set.contains(set.from_list(list.flatten(prev_rev)), line)
      })
  }
}
