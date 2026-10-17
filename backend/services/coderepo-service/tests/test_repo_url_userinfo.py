from app.services import repo_url_has_userinfo, strip_repo_url_userinfo


def test_userinfo_detected_and_masked():
    assert repo_url_has_userinfo("https://x-access-token:SECRET@github.com/o/r.git")
    assert not repo_url_has_userinfo("https://github.com/o/r.git")
    assert not repo_url_has_userinfo("https://github.com/o/r@v1.git")
    assert "SECRET" not in strip_repo_url_userinfo("https://u:SECRET@github.com/o/r.git")
