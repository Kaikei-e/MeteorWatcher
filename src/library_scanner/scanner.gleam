import index_searcher/models.{type VulnIndex, type VulnMatch}

pub fn scan_directory_parallel(
  index: VulnIndex,
  root_dir: String,
  num_workers: Int,
) -> Result(List(VulnMatch), String) {
  scan_directory_parallel_impl(index, root_dir, num_workers)
}

fn scan_directory_parallel_impl(
  index: VulnIndex,
  root_dir: String,
  num_workers: Int,
) -> Result(List(VulnMatch), String) {
  scan_directory_parallel_impl(index, root_dir, num_workers)
}
