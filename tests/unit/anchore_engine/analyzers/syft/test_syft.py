import pytest

from anchore_engine.analyzers.syft import filter_artifacts


class TestFilterArtifacts:

    @pytest.mark.parametrize(
        "relationships,expected_artifact_names",
        [
            #### filtering applied
            ([{"parent":"parent-id", "child": "child-id", "type": "ownership-by-files"}], ["parent-pkg"]),
            ([{"parent":"parent-id", "child": "child-id", "type": "ownership-by-files"}, {"parent":"another-parent-id", "child": "child-id", "type": "ownership-by-files"}], ["parent-pkg"]),
            ([{"parent":"UNCORRELATED-id", "child": "child-id", "type": "ownership-by-files"}], ["parent-pkg"]),
            #### filtering NOT applied
            ([{"parent":"parent-id", "child": "child-id", "type": "NOT-ownership-by-files"}], ["child-pkg", "parent-pkg"]),
            ([{"parent":"parent-id", "child": "NOT-child-id", "type": "ownership-by-files"}], ["child-pkg", "parent-pkg"]),
            ([], ["child-pkg", "parent-pkg"]),
        ],
    )
    def test_filter_artifact_by_relationships(
        self, relationships, expected_artifact_names
    ):
        artifacts = [
            {
                "id": "child-id",
                "name": "child-pkg",
                "type": "rpm",
            },
            {
                "id": "parent-id",
                "name": "parent-pkg",
                "type": "rpm",
            },
        ]

        actual = list(filter_artifacts(artifacts, relationships))
        assert [a["name"] for a in actual] == expected_artifact_names

    @pytest.mark.parametrize(
        "pkg_type,expected_artifact_names",
        [
            #### filtering applied
            ("bogus", []),
            ("", []),
            #### filtering NOT applied
            ("rpm", ["pkg-name"]),
            ("npm", ["pkg-name"]),
            ("apk", ["pkg-name"]),
            ("deb", ["pkg-name"]),
            ("jenkins-plugin", ["pkg-name"]),
            ("java-archive", ["pkg-name"]),

        ],
    )
    def test_filter_artifact_by_type(
        self, pkg_type, expected_artifact_names
    ):
        artifacts = [
            {
                "id": "pkg-id",
                "name": "pkg-name",
                "type": pkg_type,
            },
        ]

        actual = list(filter_artifacts(artifacts, []))
        assert [a["name"] for a in actual] == expected_artifact_names