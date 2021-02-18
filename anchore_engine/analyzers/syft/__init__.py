import collections

from anchore_engine.analyzers.utils import defaultdict_to_dict, content_hints, dig
from anchore_engine.clients.syft_wrapper import run_syft
from .handlers import modules_by_artifact_type, modules_by_engine_type

syft_OS_pkg_types = {"apk", "deb", "rpm"}


def is_ownership_allowed(child_type, parent_types):
    if child_type in syft_OS_pkg_types:
        # ensure that non-OS -> OS package ownership is not allowed.
        return set(parent_types).issubset(syft_OS_pkg_types)

    # allow all relations where the child is a non-OS package.
    return True


def filter_artifacts(artifacts):
    by_id = {a["id"]: a for a in artifacts if "id" in a}

    def filter_fn(artifact):
        # syft may do more work than what is supported in engine, ensure we only include artifacts
        # of select package types.
        if artifact["type"] not in modules_by_artifact_type:
            return False

        # some packages are owned by other packages (e.g. a python package that was installed
        # from an RPM instead of with pip), automatically allow packages that are not owned by
        # other packages.
        parent_ids = dig(
            artifact, "relations", "parentsByFileOwnership", force_default=[]
        )
        if not parent_ids:
            return True

        # by this point we know the package is owned by another package, filter the package
        # conditionally based on the types of the parent and child packages.
        parent_types = [by_id[p_id]["type"] for p_id in parent_ids if p_id in by_id]
        if is_ownership_allowed(artifact["type"], parent_types):
            # this package is allowed to be owned by the parent packages, which means it
            # should not be considered in the SBOM (thus filtered out).
            return False

        return True

    return filter(filter_fn, artifacts)


def catalog_image(imagedir):
    """
    Catalog the given image with syft, keeping only select artifacts in the returned results.
    """
    all_results = run_syft(imagedir)
    return convert_syft_to_engine(all_results)


def convert_syft_to_engine(all_results):
    """
    Do the conversion from syft format to engine format

    :param all_results:
    :return:
    """

    # transform output into analyzer-module/service "raw" analyzer json document
    nested_dict = lambda: collections.defaultdict(nested_dict)
    findings = nested_dict()

    # This is the only use case for consuming the top-level results from syft,
    # capturing the information needed for BusyBox. No artifacts should be
    # expected, and having outside of the artifacts loop ensure this will only
    # get called once.
    distro = all_results.get("distro")
    if distro and distro.get("name", "").lower() == "busybox":
        findings["package_list"]["pkgs.all"]["base"]["BusyBox"] = distro["version"]
    elif not distro or not distro.get("name"):
        findings["package_list"]["pkgs.all"]["base"]["Unknown"] = "0"

    # take a sub-set of the syft findings and invoke the handler function to
    # craft the artifact document and inject into the "raw" analyzer json
    # document
    for artifact in filter_artifacts(all_results["artifacts"]):
        handler = modules_by_artifact_type[artifact["type"]]
        handler.translate_and_save_entry(findings, artifact)

    return defaultdict_to_dict(findings)
