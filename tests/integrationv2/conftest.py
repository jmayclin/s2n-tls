import os
import subprocess
from global_flags import set_flag, S2N_PROVIDER_VERSION, S2N_FIPS_MODE, S2N_NO_PQ


def pytest_addoption(parser):
    pass
    parser.addoption("--provider-version", action="store", dest="provider-version",
                     default=None, type=str, help="Set the version of the TLS provider", required=True)
    parser.addoption("--fips-mode", action="store_true", dest="fips-mode",
                     default=False, help="S2N is running in FIPS mode")
    parser.addoption("--no-pq", action="store_true", dest="no-pq",
                     default=False, help="Turn off PQ support")
    parser.addoption("--force-javassl", action="store_true", dest="force-javassl", default=False, help="fail if the javassl provider is not available")
    parser.addoption("--force-gnutls", action="store_true", dest="force-gnutls", default=False, help="fail if the gnutls provider is not available")

def pytest_configure(config):
    """
    pytest hook that adds the function to deselect tests if the parameters
    don't makes sense.
    """
    config.addinivalue_line(
        "markers", "uncollect_if(*, func): function to unselect tests from parametrization"
    )

    provider_status = {}
    # we will error out if s2n and openssl aren't available
    provider_available["s2n"] = True
    provider_available["openssl"] = True
    # check on PATH
    if bin_available("s2nd") and bin_available("s2nc"):
        config.stash["s2n-fixture-path"] = ""
    # try to find s2n-tls/build/bin/s2n*
    else:
        # iterate back to root directory
        original_dir = os.getcwd()
        current_dir = os.getcwd()
        while (current_dir.split("/")[-1] != "s2n-tls"):
            os.chdir("..")
            current_dir = os.getcwd()
        s2n_build = current_dir + "/build/bin/"
        if bin_available(s2n_build + "s2nd") and bin_available(s2n_build + "s2nc"):
            config.stash["s2n-fixture-path"] = s2n_build
        else:
            os.chdir(original_dir)
            raise Exception("couldn't find s2nd or s2nc")
        os.chdir(original_dir)

    if not bin_available("openssl"):
        raise Exception("OpenSSL provider was not found")

    provider_available["gnutls-cli"]
    if config.getoption("force-gnutls") and not bin_available("gnutls-cli"):
        raise Exception("GnuTLS was required with --force-gnutls, but was not found")

    raise Exception(config.stash["s2n-fixture-path"])


    no_pq = config.getoption('no-pq', 0)
    fips_mode = config.getoption('fips-mode', 0)
    if no_pq == 1:
        set_flag(S2N_NO_PQ, True)
    if fips_mode == 1:
        set_flag(S2N_FIPS_MODE, True)

    set_flag(S2N_PROVIDER_VERSION, config.getoption('provider-version', None))


def pytest_collection_modifyitems(config, items):
    """
    pytest hook to modify the test arguments to call the uncollect function.
    """
    removed = []
    kept = []
    for item in items:
        m = item.get_closest_marker('uncollect_if')
        if m:
            func = m.kwargs['func']
            if func(**item.callspec.params):
                removed.append(item)
                continue
        kept.append(item)
    if removed:
        config.hook.pytest_deselected(items=removed)
        items[:] = kept

def bin_available(bin: str) -> bool:
    try:
        sp = subprocess.call(bin, timeout = 1.0)
        return True
    except:
        return False