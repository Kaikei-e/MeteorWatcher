// fetch OSV data from https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv
import gleam/http/request
import gleam/httpc
import gleam/result

pub fn osv_collector() -> Result(String, httpc.HttpError) {
  let status_ok = 200

  let url = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"

  let assert Ok(base_request) = request.to(url)
  let req = request.prepend_header(base_request, "Accept", "text/csv")

  use resp <- result.try(httpc.send(req))
  assert resp.status == status_ok

  Ok(resp.body)
}
