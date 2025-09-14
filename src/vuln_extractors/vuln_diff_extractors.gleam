import gleam/dict
import gleam/list
import gleam/option.{None, Some}

/// 複数リスト中で「出現回数ちょうど1」のIDのみを返す（O(N)）
/// - 中間の flatten を作らず、二重 fold で逐次集計
/// - 2 で飽和させる：None -> 1、Some(_) -> 2
pub fn vuln_diff_extractors(
  vulnerabilities_list: List(List(String)),
) -> List(String) {
  // 1) 出現回数マップを構築（飽和カウント）
  let freq =
    list.fold(vulnerabilities_list, dict.new(), fn(acc, one_list) {
      list.fold(one_list, acc, fn(acc2, id) {
        dict.upsert(acc2, id, fn(maybe) {
          case maybe {
            None -> 1
            // 初回
            Some(_) -> 2
            // 2回目以降は常に 2（= 2+ として扱う）
          }
        })
      })
    })

  // 2) 値が 1 のキーだけを抽出（順序は未定義なので必要なら別途ソート）
  dict.fold(freq, [], fn(out, id, count) {
    case count == 1 {
      True -> [id, ..out]
      False -> out
    }
  })
  |> list.reverse()
  // 表示順を安定させたい場合の簡易措置（辞書自体は無順序）
}
