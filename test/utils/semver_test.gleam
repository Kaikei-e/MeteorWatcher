import gleeunit
import gleeunit/should
import utils/semver

pub fn main() {
  gleeunit.main()
}

pub fn parse_version_test() {
  semver.parse_version("1.0.0")
  |> should.be_ok()

  semver.parse_version("v1.2.3")
  |> should.be_ok()

  semver.parse_version("2.1")
  |> should.be_ok()
}

pub fn version_in_range_from_zero_test() {
  semver.version_in_range_from_zero("1.0.0", "1.1.0")
  |> should.be_true()

  semver.version_in_range_from_zero("1.1.0", "1.1.0")
  |> should.be_false()

  semver.version_in_range_from_zero("1.2.0", "1.1.0")
  |> should.be_false()
}
