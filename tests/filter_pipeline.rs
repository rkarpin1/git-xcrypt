//! The vertical slice: git runs our binary as a filter and stores the result.

mod harness;

use harness::TestRepo;

const SECRET: &[u8] = b"api_key = do-not-commit-me\n";

#[test]
fn committed_blob_differs_from_the_working_tree() {
    let repo = TestRepo::init();
    repo.register_filter("git-xcrypt");
    repo.write_attributes("secrets.env filter=git-xcrypt -text\n");
    repo.write_file("secrets.env", SECRET);

    repo.commit_all("add a secret");

    repo.assert_blob_differs_from_worktree("secrets.env");
    repo.assert_worktree_eq("secrets.env", SECRET);
    repo.assert_blob_eq("secrets.env", &git_xcrypt::transform(SECRET));
}

#[test]
fn unmatched_files_are_stored_verbatim() {
    let repo = TestRepo::init();
    repo.register_filter("git-xcrypt");
    repo.write_attributes("secrets.env filter=git-xcrypt -text\n");
    repo.write_file("readme.md", b"public\n");

    repo.commit_all("add a public file");

    repo.assert_blob_eq("readme.md", b"public\n");
}
