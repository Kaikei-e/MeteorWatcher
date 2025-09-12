// fetch OSV data from gs://osv-vulnerabilities/modified_id.csv 4 hours ago
// and save it to a local file
import gleam/http/request
import gleam/httpc
import gleam/result
import gleam/string
import gleam/uri

pub fn osv_collector() -> Result(String, httpc.HttpError) {
  let status_ok = 200

  let assert Ok(url) =
    uri.parse("gs://osv-vulnerabilities/modified_id.csv")
    |> result.map_error(fn(error) {
      "Failed to parse URL " <> string.inspect(error)
    })
    |> result.map(fn(parsed) { parsed.path })

  let assert Ok(base_request) = request.to(url)
  let req = request.prepend_header(base_request, "Accept", "text/csv")

  use resp <- result.try(httpc.send(req))
  assert resp.status == status_ok

  Ok(resp.body)
}
